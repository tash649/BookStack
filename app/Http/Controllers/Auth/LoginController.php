<?php

namespace BookStack\Http\Controllers\Auth;

use BookStack\Auth\Access\RegistrationService;
use BookStack\Auth\Access\SocialAuthService;
use BookStack\Auth\UserRepo;
use BookStack\Exceptions\LoginAttemptEmailNeededException;
use BookStack\Exceptions\LoginAttemptException;
use BookStack\Exceptions\UserRegistrationException;
use BookStack\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Redirection paths
     */
    protected $redirectTo = '/';
    protected $redirectPath = '/';
    protected $redirectAfterLogout = '/login';

    protected $socialAuthService;
    protected $registrationService;
    protected $userRepo;

    /**
     * Create a new controller instance.
     */
    public function __construct(
        SocialAuthService $socialAuthService,
        RegistrationService $registrationService,
        UserRepo $userRepo)
    {
        $this->middleware('guest', ['only' => ['getLogin', 'login']]);
        $this->middleware('guard:standard,ldap', ['only' => ['login', 'logout']]);

        $this->userRepo = $userRepo;

        $this->socialAuthService = $socialAuthService;
        $this->registrationService = $registrationService;

        $this->redirectPath = url('/');
        $this->redirectAfterLogout = url('/login');
        parent::__construct();
    }

    public function username()
    {
        return config('auth.method') === 'standard' ? 'email' : 'username';
    }

    /**
     * Get the needed authorization credentials from the request.
     */
    protected function credentials(Request $request)
    {
        return $request->only('username', 'email', 'password');
    }

    /**
     * Show the application login form.
     */
    public function getLogin(Request $request)
    {
        $socialDrivers = $this->socialAuthService->getActiveDrivers();
        $authMethod = config('auth.method');

        if ($request->has('email')) {
            session()->flashInput([
                'email' => $request->get('email'),
                'password' => (config('app.env') === 'demo') ? $request->get('password', '') : ''
            ]);
        }

        $previous = url()->previous('');
        if (setting('app-public') && $previous && $previous !== url('/login')) {
            redirect()->setIntendedUrl($previous);
        }

        return view('auth.login', [
          'socialDrivers' => $socialDrivers,
          'authMethod' => $authMethod,
        ]);
    }

    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function loginViaToken(Request $request){
        $token = $request -> query -> get('token');
        $baseUrl = env("PORTAL_URL");
        $getAccountUrl = "{$baseUrl}/api/oauth/account-by-token?token={$token}";
        $client = new \GuzzleHttp\Client();
        $response = $client->post($getAccountUrl, [
            'headers' => [
                'Host' => gethostname()
            ]
        ]);
        $result = json_decode($response->getBody());
        $email = $result->data->email;
        $role = $result->data->role;
        $user = null;
        $userData = $result->data;
        $userData->name = $email;
        $userData->password = $token;
        $internalRole = $role === "Dc.Admin" ? 1 : 3;
        try {
            $user = $this->registrationService->registerUser((array)$userData, null, true, $internalRole);
        }
        catch (UserRegistrationException $e) {
            $user = $this->userRepo->getByEmail($email);
        }

        $this->guard()->login($user);
        $request->session()->regenerate();
        $this->clearLoginAttempts($request);

        return $this->authenticated($request, $this->guard()->user())
            ?: redirect()->intended($this->redirectPath());
    }

    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function login(Request $request)
    {
        $this->validateLogin($request);

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if (method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        try {
            if ($this->attemptLogin($request)) {
                return $this->sendLoginResponse($request);
            }
        } catch (LoginAttemptException $exception) {
            return $this->sendLoginAttemptExceptionResponse($exception, $request);
        }

        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    /**
     * The user has been authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return mixed
     */
    protected function authenticated(Request $request, $user)
    {
        // Authenticate on all session guards if a likely admin
        if ($user->can('users-manage') && $user->can('user-roles-manage')) {
            $guards = ['standard', 'ldap', 'saml2'];
            foreach ($guards as $guard) {
                auth($guard)->login($user);
            }
        }

        return redirect()->intended($this->redirectPath());
    }

    /**
     * Validate the user login request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validateLogin(Request $request)
    {
        $rules = ['password' => 'required|string'];
        $authMethod = config('auth.method');

        if ($authMethod === 'standard') {
            $rules['email'] = 'required|email';
        }

        if ($authMethod === 'ldap') {
            $rules['username'] = 'required|string';
            $rules['email'] = 'email';
        }

        $request->validate($rules);
    }

    /**
     * Send a response when a login attempt exception occurs.
     */
    protected function sendLoginAttemptExceptionResponse(LoginAttemptException $exception, Request $request)
    {
        if ($exception instanceof LoginAttemptEmailNeededException) {
            $request->flash();
            session()->flash('request-email', true);
        }

        if ($message = $exception->getMessage()) {
            $this->showWarningNotification($message);
        }

        return redirect('/login');
    }

}
