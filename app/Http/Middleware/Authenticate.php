<?php

namespace BookStack\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class Authenticate
{
    use ChecksForEmailConfirmation;

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        if ($this->awaitingEmailConfirmation()) {
            return $this->emailConfirmationErrorResponse($request);
        }

        $token = $request -> query -> get('token');

        if (!hasAppAccess()) {
            if ($request->ajax()) {
                return response('Unauthorized.', 401);
            }
            else if($token !== null){
                return redirect()->action('Auth\LoginController@loginViaToken', ['token' => $token]);
            }
            else {
                return redirect()->guest(url(env("PORTAL_URL")));
            }
        }

        return $next($request);
    }

    /**
     * Provide an error response for when the current user's email is not confirmed
     * in a system which requires it.
     */
    protected function emailConfirmationErrorResponse(Request $request)
    {
        if ($request->wantsJson()) {
            return response()->json([
                'error' => [
                    'code' => 401,
                    'message' => trans('errors.email_confirmation_awaiting')
                ]
            ], 401);
        }

        return redirect('/register/confirm/awaiting');
    }
}
