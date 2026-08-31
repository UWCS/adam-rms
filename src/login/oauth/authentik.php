<?php
require_once __DIR__ . '/../../common/head.php';

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\InvalidApplicationCredentialsException;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\Data;
use Hybridauth\User;

/**
 * Generic OpenID Connect adapter for Authentik (UWCS SSO).
 *
 * Mirrors Hybridauth's Keycloak/Authentiq providers but points at Authentik's
 * per-provider endpoints: /application/o/{slug}/authorize|token|userinfo.
 * The raw userinfo response (including the 'groups' claim provided by an
 * Authentik scope mapping) is stashed on the profile so the login callback
 * can do JIT role sync.
 */
class AdamRMSAuthentikProvider extends OAuth2
{
    protected $scope = 'openid profile email groups';

    protected function configure()
    {
        parent::configure();

        if (!$this->config->exists('url')) {
            throw new InvalidApplicationCredentialsException('You must define Authentik base url');
        }
        if (!$this->config->exists('provider')) {
            throw new InvalidApplicationCredentialsException('You must define Authentik provider slug');
        }

        $base = rtrim($this->config->get('url'), '/') . '/application/o/' . $this->config->get('provider') . '/';
        $this->apiBaseUrl = $base;
        $this->authorizeUrl = $base . 'authorize/';
        $this->accessTokenUrl = $base . 'token/';
    }

    public function getUserProfile()
    {
        $response = $this->apiRequest('userinfo');
        $data = new Data\Collection($response);

        if (!$data->exists('sub')) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

        $userProfile = new User\Profile();
        $userProfile->identifier = $data->get('sub');
        $userProfile->displayName = $data->get('preferred_username');
        $userProfile->email = $data->get('email');
        $userProfile->firstName = $data->get('given_name');
        $userProfile->lastName = $data->get('family_name');
        $userProfile->emailVerified = $data->get('email_verified');

        // Raw userinfo for the callback (groups claim etc.)
        $userProfile->data['authentik_userinfo'] = $response;
        if ($data->exists('groups')) {
            $userProfile->data['authentik_groups'] = $data->get('groups');
        }
        return $userProfile;
    }
}

/**
 * Blind-apply the Authentik group -> instance position mapping.
 *
 * Adds (or reactivates) a userInstances row for every position a group grants,
 * and soft-deletes rows for positions the user no longer holds. Only rows for
 * positions listed in the role map are touched - anything else is left alone.
 */
function syncAuthentikInstanceRoles($userId, $wantedPositions, $managedPositions)
{
    global $DBLIB;

    if (count($managedPositions) < 1) return;

    $DBLIB->where("users_userid", $userId);
    $DBLIB->where("instancePositions_id", $managedPositions, "IN");
    $existing = $DBLIB->get("userInstances", null, ["userInstances_id", "instancePositions_id", "userInstances_deleted"]);

    $rowsByPosition = [];
    foreach ($existing as $row) {
        $rowsByPosition[$row['instancePositions_id']][] = $row;
    }

    // Add or reactivate rows for currently-held positions
    foreach ($wantedPositions as $positionId => $label) {
        $positionId = (int)$positionId;
        if ($positionId < 1) continue;

        $found = false;
        foreach ($rowsByPosition[$positionId] ?? [] as $row) {
            if ($row['userInstances_deleted'] == '0') {
                $found = true;
                break;
            }
            // Deleted row exists - reactivate it rather than creating a duplicate
            $DBLIB->where("userInstances_id", $row['userInstances_id']);
            $DBLIB->update("userInstances", [
                "userInstances_deleted" => 0,
                "userInstances_archived" => null,
                "userInstances_label" => $label
            ]);
            $found = true;
            break;
        }
        if ($found) continue;

        $DBLIB->insert("userInstances", [
            "users_userid" => $userId,
            "instancePositions_id" => $positionId,
            "userInstances_label" => $label
        ]);
    }

    // Soft-delete rows whose position is no longer held
    foreach ($rowsByPosition as $positionId => $rows) {
        if (isset($wantedPositions[$positionId])) continue;
        foreach ($rows as $row) {
            if ($row['userInstances_deleted'] == '0') {
                $DBLIB->where("userInstances_id", $row['userInstances_id']);
                $DBLIB->update("userInstances", ["userInstances_deleted" => 1]);
            }
        }
    }
}

$PAGEDATA['pageConfig'] = ["TITLE" => "Login with UWCS"];

$authentikUrl = $CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_URL");
$authentikProviderSlug = $CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_PROVIDER");
$authentikClientId = $CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_KEYS_ID");
$authentikClientSecret = $CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_KEYS_SECRET");
$authentikAvailable = $authentikUrl != false and $authentikProviderSlug != false and $authentikClientId != false and $authentikClientSecret != false;

if (!$authentikAvailable) {
    //Display normal login page if Authentik isn't configured
    header("Location: " . $CONFIG['ROOTURL'] . "/login");
    exit;
}

$configObject = [
    "callback" => $CONFIG['ROOTURL'] . '/login/oauth/authentik.php',
    "url" => rtrim($authentikUrl, '/'),
    "provider" => $authentikProviderSlug,
    "keys" => [
        "id" => $authentikClientId,
        "secret" => $authentikClientSecret
    ],
    "scope" => $CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_SCOPE"),
    "supportRequestState" => true,
];

try {
    $adapter = new AdamRMSAuthentikProvider($configObject);
    $adapter->authenticate();
} catch (\Exception $e) {
    //Issue with auth state, which is a problem with the user's browser. We can't do anything about this, so just show an error
    $PAGEDATA['ERROR'] = "Sorry, something went wrong authenticating with UWCS.";
    die($TWIG->render('login/error.twig', $PAGEDATA));
}
$userProfile = $adapter->getUserProfile();
$adapter->disconnect(); //Disconnect this authentication from the session, so they can pick another account

if (strlen($userProfile->identifier) < 1) {
    //ISSUE WITH PROFILE
    $PAGEDATA['ERROR'] = "Sorry, something went wrong authenticating with UWCS";
    echo $TWIG->render('login/error.twig', $PAGEDATA);
    exit;
}

// Normalise the groups claim (Authentik scope mappings may emit names or serialized group objects)
$groups = [];
foreach ((array)($userProfile->data['authentik_groups'] ?? []) as $group) {
    if (is_array($group) && isset($group['name'])) $groups[] = $group['name'];
    elseif (is_string($group) && strlen($group) > 0) $groups[] = $group;
}
$groups = array_values(array_unique($groups));

// Roles: Authentik group name -> instancePositions_id
$roleMap = json_decode($CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_INSTANCE_ROLE_MAP") ?: '{}', true);
if (!is_array($roleMap)) $roleMap = [];

$wantedPositions = [];
foreach ($groups as $group) {
    if (isset($roleMap[$group])) $wantedPositions[(int)$roleMap[$group]] = $group;
}
$managedPositions = array_values(array_unique(array_map('intval', array_values($roleMap))));

$DBLIB->where("users_oauth_authentikid", $userProfile->identifier);
$DBLIB->where("users_deleted", 0);
$user = $DBLIB->getOne("users", ["users.users_suspended", "users.users_userid", "users.users_hash", "users.users_emailVerified", "users.users_email"]);
if ($user) {
    if ($user['users_suspended'] != '0') {
        $PAGEDATA['ERROR'] = "Sorry, your user account is suspended";
        echo $TWIG->render('login/error.twig', $PAGEDATA);
        exit;
    }

    // JIT role sync: blind-apply the group mapping both ways
    syncAuthentikInstanceRoles($user['users_userid'], $wantedPositions, $managedPositions);

    //Log them in successfully
    $GLOBALS['AUTH']->generateToken($user['users_userid'], false, "Web - UWCS SSO", "web-session");
    header("Location: " . (isset($_SESSION['return']) ? $_SESSION['return'] : $CONFIG['ROOTURL']));
    exit;
}

//See if an email is found, but not linked to Authentik. We don't want to auto-link them because its a good attack vector
if (isset($userProfile->email) && strlen($userProfile->email) > 0) {
    $DBLIB->where("users_email", strtolower($userProfile->email));
    $user = $DBLIB->getOne("users", ["users.users_userid"]);
    if ($user) {
        $PAGEDATA['ERROR'] = "An AdamRMS account associated with the email address you selected has been found. Please ask your administrator to link your account to UWCS SSO.";
        echo $TWIG->render('login/error.twig', $PAGEDATA);
        exit;
    }
}

// They don't have an account. Only create one if SSO signup is enabled AND they hold a mapped role
if ($CONFIGCLASS->get("AUTH_PROVIDERS_AUTHENTIK_SIGNUP") !== 'Enabled') {
    $PAGEDATA['ERROR'] = "We couldn't find an existing account and SSO signups are disabled. Please contact your business administrator.";
    echo $TWIG->render('login/error.twig', $PAGEDATA);
    exit;
}
if (count($wantedPositions) < 1) {
    $PAGEDATA['ERROR'] = "Your UWCS account is not in a group with access to this system.";
    echo $TWIG->render('login/error.twig', $PAGEDATA);
    exit;
}

//Okay we can't find them, so lets sign them up to an account (identity comes from Authentik - no password)
$username = isset($userProfile->displayName) && strlen($userProfile->displayName) > 0
    ? preg_replace("/[^a-zA-Z0-9]+/", "", $userProfile->displayName)
    : preg_replace("/[^a-zA-Z0-9]+/", "", ($userProfile->firstName ?? '') . ($userProfile->lastName ?? ''));
if (strlen($username) < 1) $username = "user";
while ($AUTH->usernameTaken($username)) {
    $username .= "1";
}
$data = [
    'users_email' => (isset($userProfile->email) && strlen($userProfile->email) > 0) ? strtolower($userProfile->email) : null,
    'users_emailVerified' => ($userProfile->emailVerified == 1 && isset($userProfile->email) && strlen($userProfile->email) > 0) ? 1 : 0,
    'users_oauth_authentikid' => $userProfile->identifier,
    'users_username' => $username,
    'users_name1' => $userProfile->firstName ?? "",
    'users_name2' => $userProfile->lastName ?? "",
    'users_hash' => $CONFIG['AUTH_NEXTHASH']
];
$newUser = $DBLIB->insert("users", $data);
if (!$newUser) {
    $PAGEDATA['ERROR'] = "Sorry something went wrong trying to create a new user account";
    echo $TWIG->render('login/error.twig', $PAGEDATA);
    exit;
}
$bCMS->auditLog("INSERT", "users", json_encode($data), null, $newUser);

//Grant their roles immediately so the first login lands them in the right place
syncAuthentikInstanceRoles($newUser, $wantedPositions, $managedPositions);

$GLOBALS['AUTH']->generateToken($newUser, false, "Web - UWCS SSO", "web-session");
header("Location: " . (isset($_SESSION['return']) ? $_SESSION['return'] : $CONFIG['ROOTURL']));
exit;