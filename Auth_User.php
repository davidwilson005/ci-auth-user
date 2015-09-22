<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Auth User Library Class
 *
 * This class is a library class that authenticates a user
 *
 * @package     CodeIgniter
 * @category    Libraries
 */
class Auth_User {

    // private variables for holding user information
    private $_user_id;
    private $_username;
    private $_is_admin;
    private $_group_array;
    private $_language_array;
    private $_site_array;

    // this holds a reference to the CI superobject
    private $_CI;

    /**
     * Constructor
     *
     * Sets the CI superobject
     *
     * @access  public
     */
    public function __construct() {

        // set CI superobject
        $this->_CI = get_instance();
    }

    /**
     * Fetch User Id
     *
     * Fetch authenticated user id
     *
     * @access  public
     * @return  int
     */
    public function fetch_user_id() {

        if (!isset($this->_user_id)) {
            $this->_check_user_session();
        }

        return $this->_user_id;
    }

    /**
     * Fetch Username
     *
     * Fetch authenticated username
     *
     * @access  public
     * @return  string
     */
    public function fetch_username() {

        if (!isset($this->_user_id)) {
            $this->_check_user_session();
        }

        return $this->_username;
    }

    /**
     * Fetch User
     *
     * Fetch authenticated username and user id
     *
     * @access  public
     * @return  array
     */
    public function fetch_user() {

        if ( !isset($this->_user_id) || !isset($this->_username) ) {
            $this->_check_user_session();
        }

        return array('user_id' => $this->_user_id, 'username' => $this->_username);
    }

    /**
     * Fetch User Info
     *
     * Fetch info from the user info table for the current user
     *
     * @access  public
     * @return  array
     */
    public function fetch_user_info() {

        if ( !isset($this->_user_id) ) {
            $this->_check_user_session();
        }

        // fetch user info
        $this->_CI->db->from('user_info');
        $this->_CI->db->where('user_id', $this->_user_id);
        $query = $this->_CI->db->get();
        $row = $query->row_array();
        $query->free_result();

        return $row;
    }

    /**
     * Fetch Group List
     *
     * Fetch a list of groups the user is in
     *
     * @access  public
     * @return  array
     */
    public function fetch_group_list() {

        if (!isset($this->_group_array)) {
            $this->_set_group_array();
        }

        return $this->_group_array;
    }

    /**
     * Fetch Language List
     *
     * Fetch a list of languages the user is in
     *
     * @access  public
     * @return  array
     */
    public function fetch_language_list() {

        if (!isset($this->_language_array)) {
            $this->_set_language_array();
        }

        return $this->_language_array;
    }

    /**
     * Fetch Site List
     *
     * Fetch a list of site the user is in
     *
     * @access  public
     * @return  array
     */
    public function fetch_site_list() {

        if (!isset($this->_site_array)) {
            $this->_set_site_array();
        }

        return $this->_site_array;
    }

    /**
     * Is Logged In
     *
     * Determine if a user is logged in
     *
     * @access  public
     * @return  bool
     */
    public function is_logged_in() {

        // get user id
        if (!isset($this->_user_id)) {
            $this->_check_user_session();
        }

        // check if this is public user or not
        if ($this->_user_id == PUBLIC_USER_ID) {
            return FALSE;
        } else {
            return TRUE;
        }
    }

    /**
     * Is Admin
     *
     * Check if the logged in user is an admin
     *
     * @access  public
     * @return  bool
     */
    public function is_admin() {

        if (!isset($this->_is_admin)) {
            $this->_set_is_admin();
        }

        // otherwise return false
        return $this->_is_admin;
    }

    /**
     * Is Login Locked
     *
     * Determine is the user is locked out from logging in
     *
     * @access  public
     * @return  array
     */
    public function is_login_locked() {

        // get users network address
        $network_address = $this->_fetch_network_address();

        // check if there is a login attempts entry
        $this->_CI->db->where('network_address', $network_address);
        $query = $this->_CI->db->get('user_login_attempt');

        if ($query->num_rows()) {

            // get row
            $row = $query->row();
            $query->free_result();

            // check if they are locked out
            $total_time = time() - $row->lockout_start_time;
            if ( $total_time <= ( LOGIN_LOCKOUT_TIME * 60) ) {

                // return how much longer they are locked out for
                $ret_array = array(
                    'result'    => TRUE,
                    'message'   => ceil(LOGIN_LOCKOUT_TIME - ($total_time / 60))
                );

                return $ret_array;

            // they are not locked out anymore, delete their entry if they were locked out
            } elseif ($row->attempt_count == LOGIN_ATTEMPTS) {

                $this->_delete_login_attempt();
                return array('result' => FALSE);
            }

        } else {
            $query->free_result();
            return array('result' => FALSE);
        }
    }

    /**
     * Has Language
     *
     * Check if authenticated user is associated with a language
     *
     * @access  public
     * @param   int     language_id
     * @return  bool
     */
    public function has_language($language_id = NULL) {

        // if this is not a multi-language site, they would have this language
        if (!$this->_CI->config->item('is_multi_language')) return TRUE;

        // make sure language_id was passed
        if (empty($language_id)) return FALSE;

        if (!isset($this->_language_array)) {
            $this->_set_language_array();
        }

        if (array_key_exists($language_id, $this->_language_array))  {
            return $this->_language_array[$language_id];
        } else {
            return FALSE;
        }
    }

    /**
     * Has Site
     *
     * Check if authenticated user is associated with a site
     *
     * @access  public
     * @param   int     language_id
     * @return  bool
     */
    public function has_site($site_id = NULL) {

        // if this is not a multi-language site, they would have this site
        if (!$this->_CI->config->item('is_multi_site')) return TRUE;

        // make sure site_id was passed
        if (empty($site_id)) return FALSE;

        if (!isset($this->_site_array)) {
            $this->_set_site_array();
        }

        if (array_key_exists($site_id, $this->_site_array))  {
            return $this->_site_array[$site_id];
        } else {
            return FALSE;
        }
    }

    /**
     * Login User
     *
     * Login a user
     *
     * @access  public
     * @param   string  username
     * @param   string  password
     * @return  bool
     */
    public function login_user($username, $password) {

        // encrypt password
        $crypt_password = $this->encrypt_user_password($password);

        // authorize their user credientials against the database
        if ($user_id = $this->auth_user($username, $crypt_password)) {

            // delete login attempts
            $this->_delete_login_attempt();

            // set user session
            $this->_set_user_session($username, $password);

            // set user variables
            $this->_user_id = $user_id;
            $this->_username = $username;

            // set last login
            $this->_set_last_login();

            return TRUE;
        } else {

            // set login attempt
            $this->_set_login_attempt();

            // delete session
            $this->_delete_user_session();

            // set public
            $this->_set_user_public();

            return FALSE;
        }
    }

    /**
     * Auth User
     *
     * Authenticate a username and password against the database
     *
     * @access  public
     * @param   string  username
     * @param   string  password
     * @return  mixed
     */
    public function auth_user($username = NULL, $crypt_password = NULL) {

        // make sure a username and password was passed
        if (!$username || !$crypt_password) return false;

        // set query parameters
        $query_params = array(
            'LOWER(username)'   => strtolower($username),
            'user_password'     => $crypt_password,
            'active'            => 1,
            'deleted'           => 0
        );
        $this->_CI->db->select('id');
        $query = $this->_CI->db->get_where('user', $query_params, 1, 0);

        // check if they are a valid user
        if ($query->num_rows() == 1) {
            $row = $query->row();
            $query->free_result();

            return $row->id;
        } else {

            $query->free_result();
            return FALSE;
        }
    }

    /**
     * Logout User
     *
     * Logout a user
     *
     * @access  public
     */
    public function logout_user() {

        // delete user session
        $this->_delete_user_session();

        // set them to public
        $this->_set_user_public();
    }

    /**
     * Encrypt User Password
     *
     * Encrypt a password
     *
     * @access  public
     * @param   string  password
     * @return  string
     */
    public function encrypt_user_password($password) {

        // use encryption library to encrypt password
        $this->_CI->load->library('encrypt');

        // return encrypted password
        return $this->_CI->encrypt->sha1($password . $this->_CI->config->item('encryption_key'));

    }

    /**
     * Fetch User Session
     *
     * Fetches a users CI session cookie
     *
     * @access  private
     * @return  mixed
     */
    private function _fetch_user_session() {

        // load session library
        //$this->_CI->load->library('session');

        // check if session exists
        $username = $this->_CI->session->userdata('username');
        $crypt_password = $this->_CI->session->userdata('crypt_password');

        if (!empty($username) && !empty($crypt_password)) {

            // return array of user data
            return array(
                'username'          => $username,
                'crypt_password'    => $crypt_password
            );
        } else {
            return FALSE;
        }

    }

    /**
     * Fetch Network Address
     *
     * Fetch their network address based on their IP address
     *
     * @access  private
     */
    private function _fetch_network_address() {

        // get the users ip address
        $ip = $_SERVER['REMOTE_ADDR'];

        // convert to network address
        return sprintf("%u", ip2long($ip));
    }

    /**
     * Set Last Login
     *
     * Sets their last login in the database
     *
     * @access  private
     */
    private function _set_last_login() {

        // fetch user_id
        $user_id = $this->fetch_user_id();

        $this->_CI->db->set('last_login', 'current_login', FALSE);
        $this->_CI->db->set('current_login', time());
        $this->_CI->db->where('id', $user_id);
        $this->_CI->db->update('user');
    }

    /**
     * Set User Public
     *
     * Sets the active user as the public user
     *
     * @access  private
     */
    private function _set_user_public() {
        
        $this->_user_id  = PUBLIC_USER_ID;
        $this->_username = PUBLIC_USERNAME;
    }

    /**
     * Set User Session
     *
     * Sets a users CI session cookie
     *
     * @access  private
     * @param   string  username
     * @param   string  password
     */
    private function _set_user_session($username = NULL, $password = NULL) {

        // make sure a username and password was passed
        if (empty($username) || empty($password)) return false;

        // load session library
        //$this->_CI->load->library('session');

        // set user session
        $this->_CI->session->set_userdata('username', $username);
        $this->_CI->session->set_userdata('crypt_password', $this->encrypt_user_password($password));
    }

    /**
     * Set Language Array
     *
     * Sets private array of languages a user is associated with
     *
     * @access  private
     */
    private function _set_language_array() {

        // fetch user_id
        $user_id = $this->fetch_user_id();

        // select all languages
        // left join users for is_in_language flag
        $this->_CI->db->select('L.*');
        $this->_CI->db->select('COUNT(user_id) as is_in_language');
        $this->_CI->db->from('language L');
        $this->_CI->db->join('user_language UL', "L.id = UL.language_id AND UL.user_id = '".(int)$user_id."'", 'left');
        $this->_CI->db->group_by('L.id');
        $query = $this->_CI->db->get();

        // put in language_array
        $this->_language_array = array();
        foreach ($query->result_array() as $language) {

            if (($language['is_in_language']) || ($this->is_admin())) {
                $this->_language_array[$language['id']] = TRUE;
            } else {
                $this->_language_array[$language['id']] = FALSE;
            }
        }
        $query->free_result();

        // check groups associated with languages
        $this->_CI->db->distinct('L.language_id');
        $this->_CI->db->from('group_language L');
        $this->_CI->db->join('user_group G', 'L.group_id = G.group_id');
        $this->_CI->db->where('G.user_id', $user_id);
        $query = $this->_CI->db->get();

        foreach ($query->result_array() as $language) {
            $this->_language_array[$language['language_id']] = TRUE;
        }
        $query->free_result();

    }

    /**
     * Set Site Array
     *
     * Sets private array of sites a user is associated with
     *
     * @access  private
     */
    private function _set_site_array() {

        // fetch user_id
        $user_id = $this->fetch_user_id();

        // select all sites
        // left join users for is_in_site flag
        $this->_CI->db->select('S.*');
        $this->_CI->db->select('COUNT(user_id) as is_in_site');
        $this->_CI->db->from('site S');
        $this->_CI->db->join('user_site US', "S.id = US.site_id AND US.user_id = '".(int)$user_id."'", 'left');
        $this->_CI->db->group_by('S.id');
        $query = $this->_CI->db->get();

        // put in site_array
        $this->_site_array = array();
        foreach ($query->result_array() as $site) {

            if (($site['is_in_site']) || ($this->is_admin())) {
                $this->_site_array[$site['id']] = TRUE;
            } else {
                $this->_site_array[$site['id']] = FALSE;
            }
        }
        $query->free_result();

        // check groups associated with sites
        $this->_CI->db->distinct('S.site_id');
        $this->_CI->db->from('group_site S');
        $this->_CI->db->join('user_group G', 'S.group_id = G.group_id');
        $this->_CI->db->where('G.user_id', $user_id);
        $query = $this->_CI->db->get();

        foreach ($query->result_array() as $site) {
            $this->_site_array[$site['site_id']] = TRUE;
        }
        $query->free_result();

    }

    /**
     * Set Group Array
     *
     * Sets private array of groups a user is associated with
     *
     * @access  private
     */
    private function _set_group_array() {

        // fetch user_id
        $user_id = $this->fetch_user_id();

        // build query to fetch groups
        $this->_CI->db->select('group_id');
        $this->_CI->db->from('user_group');
        $this->_CI->db->where('user_id', $user_id);
        $query = $this->_CI->db->get();

        // put in group array
        $this->_group_array = array();
        foreach ($query->result_array() as $row) {
            $this->_group_array[] = $row['group_id'];
        }
        $query->free_result();

    }

    /**
     * Set Login Attempt
     *
     * Increment a failed login attempt
     *
     * @access  private
     */
    private function _set_login_attempt() {

        // get users network address
        $network_address = $this->_fetch_network_address();

        // get login attempt entry
        $this->_CI->db->where('network_address', $network_address);
        $query = $this->_CI->db->get('user_login_attempt');

        // check if this entry exists
        if ($query->num_rows()) {

            // get row
            $row = $query->row();
            $query->free_result();

            // check if they are already locked out
            if ( (time() - $row->lockout_start_time) <= ( LOGIN_LOCKOUT_TIME * 60) ) return;

            // check how much time they have been attempting to login
            if ((time() - $row->attempt_start_time) <= (LOGIN_ATTEMPT_TIME * 60)) {

                // increment login attempts
                $attempt_count = $row->attempt_count + 1;

                // set login attemps
                $this->_CI->db->set('attempt_count', $attempt_count);

                // check if they are now locked out
                if ($attempt_count == LOGIN_ATTEMPTS) {
                    $this->_CI->db->set('lockout_start_time', time());

                }

                $this->_CI->db->where('network_address', $network_address);
                $this->_CI->db->update('user_login_attempt');


            // reset the login attempts and time
            } else {

                $this->_CI->db->set('attempt_start_time', time());
                $this->_CI->db->set('attempt_count', 1);
                $this->_CI->db->set('lockout_start_time', NULL);
                $this->_CI->db->where('network_address', $network_address);
                $this->_CI->db->update('user_login_attempt');
            }

        // add login attempt
        } else {

            $query->free_result();

            $this->_CI->db->set('network_address', $network_address);
            $this->_CI->db->set('attempt_start_time', time());
            $this->_CI->db->set('attempt_count', 1);
            $this->_CI->db->insert('user_login_attempt');
        }
    }

    /**
     * Set Is Admin
     *
     * Set private bool of is admin
     *
     * @access  private
     */
    private function _set_is_admin() {

        // fetch user_id
        $user_id = $this->fetch_user_id();

        // check if this user is an admin
        if ($user_id == ADMIN_USER_ID) {
            $this->_is_admin = TRUE;
            return;

        // check if this user is public
        } elseif ($user_id == PUBLIC_USER_ID) {
            $this->_is_admin = FALSE;
            return;
        }

        // fetch list of groups
        if (!isset($this->_group_array)) {
            $this->_set_group_array();
        }

        // check if this user is in an admin group
        $this->_is_admin = in_array(ADMIN_GROUP_ID, $this->_group_array);
    }

    /**
     * Check User Session
     *
     * Checks a users CI session cookie against the database
     *
     * @access  private
     */
    private function _check_user_session() {

        // get user session
        if ($user_session = $this->_fetch_user_session()) {

            // authenticate session against the database
            if ($user_id = $this->auth_user($user_session['username'], $user_session['crypt_password'])) {

                $this->_user_id = $user_id;
                $this->_username = strtolower($user_session['username']);

            // if session did not authenticate
            } else {

                // delete session
                $this->_delete_user_session();

                // set them as public
                $this->_set_user_public();
            }

        // if the session does not exist, set them as public
        } else {

            $this->_set_user_public();
        }
    }

    /**
     * Delete Login Attempt
     *
     * Delete the record of their login attempts and lockout information
     *
     * @access  private
     */
    private function _delete_login_attempt() {

        // get users network address
        $network_address = $this->_fetch_network_address();

        // delete login attempt record
        $this->_CI->db->where('network_address', $network_address);
        $this->_CI->db->delete('user_login_attempt');
    }

    /**
     * Delete User Session
     *
     * Deletes a users CI session cookie
     *
     * @access  private
     */
    private function _delete_user_session() {

        // use session library
        //$this->_CI->load->library('session');

        // delete user session
        $this->_CI->session->unset_userdata('username');
        $this->_CI->session->unset_userdata('crypt_password');

    }
}
// END Auth_User class

/* End of file Auth_User.php */
/* Location: ./application/libraries/Auth_User.php */