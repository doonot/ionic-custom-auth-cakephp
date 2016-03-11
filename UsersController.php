App::import('Vendor', 'firebase/php-jwt/src/JWT');
	
/**
 * Users Controller
 *
 * @property User $User
 * @property PaginatorComponent $Paginator
 */
class UsersController extends AppController {

	public $components = array('Paginator', 'RequestHandler');

	// ionic custom auth
	public function auth() {

		// get all parameters
		$redirectUri = $this->request->query['redirect_uri']; 
		$state = $this->request->query['state']; 
		$token = $this->request->query['token'];
		$sharedSecret = "some-shared-secred";

		// decode JWT token using HS256 algorithm as used by ionic
		$decoded = JWT::decode($token, $sharedSecret, array('HS256')); // $decoded is an object, not an array and has to be accessed using ->

		// get current password hash from database
		$usertmp = $this->User->find('first',
			array(
				'conditions' => array(
					'User.email' => $decoded->data->email
				),
				'fields' => array(
					'password'
				)
			)
		);

		// generate hash for current password
		$newHash = Security::hash($decoded->data->password, 'blowfish', $usertmp['User']['password']);

		// get user
		$user = $this->User->find('first', array(
			'conditions' => array(
				'User.email' => $decoded->data->email,
				'User.password' => $newHash,
				'User.is_active' => 1
			),
			'fields' => array(
				'id',
				'prename',
				'lastname',
				'is_active',
				'session_id',
				'username',
				'avatar',
				'photo_dir',
				'email'
			)
		));

		if(empty($user)) {
			// return 401 auth error
			throw new UnauthorizedException(__('auth error'));
		} else {
			$payload = array(
				'user_id' => $user['User']['id']
			);

			// encode payload
			$outgoingToken = JWT::encode($payload, $sharedSecret);

			// redirect back to ionic
			$url = $redirectUri . '&token=' . $outgoingToken . '&state=' . $state . '&redirect_uri=' . 'https://api.ionic.io/auth/integrations/custom/success';
			$this->redirect($url);
		}
	}
}
