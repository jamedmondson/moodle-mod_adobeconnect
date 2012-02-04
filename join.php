<?php // $Id: join.php,v 1.1.2.10 2011/04/05 15:27:02 adelamarre Exp $

/**
 * This page assigns roles on the Adobe Connect Server as required
 * before redirecting the user to the correct meeting URL
 *
 * @author  Your Name <adelamarre@remote-learner.net>
 * @version $Id: join.php,v 1.1.2.10 2011/04/05 15:27:02 adelamarre Exp $
 * @package mod/adobeconnect
 */

require_once(dirname(dirname(dirname(__FILE__))).'/config.php');
require_once(dirname(__FILE__).'/locallib.php');
require_once(dirname(__FILE__).'/connect_class.php');
require_once(dirname(__FILE__).'/connect_class_dom.php');

$id       = required_param('id', PARAM_INT); // course_module ID, or
$groupid  = required_param('groupid', PARAM_INT);
$sesskey  = required_param('sesskey', PARAM_ALPHANUM);

if (! $cm = get_coursemodule_from_id('adobeconnect', $id)) {
    error('Course Module ID was incorrect');
}

if (! $course = get_record('course', 'id', $cm->course)) {
    error('Course is misconfigured');
}

if (! $adobeconnect = get_record('adobeconnect', 'id', $cm->instance)) {
    error('Course module is incorrect');
}

require_login($course, true, $cm);

global $CFG, $USER;

// Check if the user's email is the Connect Pro user's login
$usrobj = new stdClass();
$usrobj = clone($USER);

if (isset($CFG->adobeconnect_email_login) and !empty($CFG->adobeconnect_email_login)) {
    $usrobj->username = $usrobj->email;
}

$usrcanjoin = false; //Check group affiliation
$limitedaccess = false; //track whether should be entering as a guest despite what role might be held in parent contexts

// groupings are ignored when not enabled
if (empty($CFG->enablegroupings)) {
    $cm->groupingid = 0;
}

//All groups for this grouping in course
//mimic return format of groups_get_user_groups()
$crsgroups = groups_get_all_groups($course->id, 0, $cm->groupingid);
$crsgroups[$cm->groupingid] = array_keys($crsgroups);

//group(s) to display meeting(s) for
$groups = array();
//group(s) user is enrolled in
$context = get_context_instance(CONTEXT_MODULE, $id);
if ($cm->groupmode == NOGROUPS) {
    $allowedgroups = array();
} elseif (has_capability('moodle/site:accessallgroups', $context)) {
    $allowedgroups =  $crsgroups;
} else {
    $allowedgroups = groups_get_user_groups($course->id, $USER->id);
    if (empty($allowedgroups) || !isset($allowedgroups[$cm->groupingid]) || empty($allowedgroups[$cm->groupingid])) {
        notice(get_string('usergrouprequired', 'adobeconnect'));
    }
}

$context = get_context_instance(CONTEXT_MODULE, $id);
if ($cm->groupmode == NOGROUPS) {
    $usrcanjoin = true;
} elseif (has_capability('moodle/site:accessallgroups', $context)) {
    $usrcanjoin = true;
} elseif (in_array($groupid, $allowedgroups[$cm->groupingid])) {
    $usrcanjoin = true;
} elseif ($adobeconnect->meetingpublic) {
    if ($cm->groupmode == VISIBLEGROUPS) {
        //Groups more important than role/private/public.
        //This is the equivalent of joining with guest access via URL
        $usrcanjoin = true;
        $limitedaccess = true;
    } else {
        // SEPARATEGROUPS. Only access via URL because the button
        // to here will never display due to the way Moodle
        // handles groups & the groups menu
    }
}

// user has to be in a group
if ($usrcanjoin and confirm_sesskey($sesskey)) {

    $usrprincipal = 0;
    $validuser = true;
    $groupobj = groups_get_group($groupid);

    // Get the meeting sco-id
    $meetingscoid = get_field('adobeconnect_meeting_groups', 'meetingscoid',
                              'instanceid', $cm->instance, 'groupid', $groupid);

    $aconnect = aconnect_login();

    // Check if the meeting still exists on the Adobe server
    $meetfldscoid = aconnect_get_folder($aconnect, 'meetings');
    $filter = array('filter-sco-id' => $meetingscoid);
    $meeting = aconnect_meeting_exists($aconnect, $meetfldscoid, $filter);

    if (!empty($meeting)) {
        $meeting = current($meeting);
    }

    if (!($usrprincipal = aconnect_user_exists($aconnect, $usrobj))) {
        if (!($usrprincipal = aconnect_create_user($aconnect, $usrobj))) {
            // DEBUG
            print_object("error creating user");
            print_object($aconnect->_xmlresponse);
            $validuser = false;
            debugging("error creating user", DEBUG_DEVELOPER);
        }

    }

    $context = get_context_instance(CONTEXT_MODULE, $id);

    // Check the user's capabilities and assign them the Adobe Role
    if (!empty($meetingscoid) and !empty($usrprincipal) and !empty($meeting)) {
    $context = get_context_instance(CONTEXT_MODULE, $id);        
    if (has_capability('mod/adobeconnect:meetinghost', $context) && !$limitedaccess) {
            if (!aconnect_check_user_perm($aconnect, $usrprincipal, $meetingscoid, ADOBE_HOST, true)) {
                $validuser = false;
                debugging('error assigning user adobe host role',  DEBUG_DEVELOPER);
            }
        } elseif (has_capability('mod/adobeconnect:meetingpresenter', $context) && !$limitedaccess) {
            if (!aconnect_check_user_perm($aconnect, $usrprincipal, $meetingscoid, ADOBE_PRESENTER, true)) {
                $validuser = false;
                debugging('error assigning user adobe presenter role', DEBUG_DEVELOPER);
            }
        } elseif (has_capability('mod/adobeconnect:meetingparticipant', $context) && !$limitedaccess) {
            if (!aconnect_check_user_perm($aconnect, $usrprincipal, $meetingscoid, ADOBE_PARTICIPANT, true)) {
                $validuser = false;
                debugging('error assigning user adobe participant role', DEBUG_DEVELOPER);
            }
        } else {
            // Check if meeting is public and allow them to join
            if ($adobeconnect->meetingpublic) {
                // if for a public meeting the user does not not have either of presenter or participant capabilities then give
                // the user the participant role for the meeting
                if (aconnect_check_user_perm($aconnect, $usrprincipal, $meetingscoid, ADOBE_PARTICIPANT, true)) {
                    $validuser = true;
                } else {
                    print_object('error assign user adobe particpant role (guest access to public meeting)');
                    $validuser = false;
                }
            } else {
                $validuser = false;
            }
        }
    } else {
        $validuser = false;
        notice(get_string('unableretrdetails', 'adobeconnect'));
    }

    aconnect_logout($aconnect);

    // User is either valid or invalid, if valid redirect user to the meeting url
    if (empty($validuser)) {
        notice(get_string('notparticipant', 'adobeconnect'));
    } else {

        $protocol = 'http://';
        $https = false;
        $login = $usrobj->username;

        if (isset($CFG->adobeconnect_https) and (!empty($CFG->adobeconnect_https))) {

            $protocol = 'https://';
            $https = true;
        }

        $aconnect = new connect_class_dom($CFG->adobeconnect_host, $CFG->adobeconnect_port,
                                          '', '', '', $https);
        $aconnect->request_http_header_login(1, $login);

        // Include the port number only if it is a port other than 80
        $port = '';

        if (!empty($CFG->adobeconnect_port) and (80 != $CFG->adobeconnect_port)) {
            $port = ':' . $CFG->adobeconnect_port;
        }

        add_to_log($course->id, 'adobeconnect', 'join meeting',
                   "join.php?id=$cm->id&groupid=$groupid&sesskey=$sesskey", "Join meeting {$adobeconnect->name}", $cm->id);

        redirect($protocol . $CFG->adobeconnect_meethost . $port
                 . $meeting->url
                 . '?session=' . $aconnect->get_cookie());
    }
} else {
    notice(get_string('usernotenrolled', 'adobeconnect'));
}
?>