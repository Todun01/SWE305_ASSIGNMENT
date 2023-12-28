<?php

namespace App\Http\Controllers;

use App\Mail\SendMailreset;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Carbon\Carbon;
use App\Http\Requests\UpdatePasswordRequest;


class ApiController extends Controller
{
    public function register(Request $request)
    {
     //Validate data
        $data = $request->only('name', 'email', 'password');
        $validator = Validator::make($data, [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6|max:50'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        //Request is valid, create new user
        $user = User::create([
         'name' => $request->name,
         'email' => $request->email,
         'password' => bcrypt($request->password)
        ]);

        //User created, return success response
        return response()->json([
            'success' => true,
            'message' => 'User created successfully',
            'data' => $user
        ], Response::HTTP_OK);
    }
 
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');

        //validate credentials
        $validator = Validator::make($credentials, [
            'email' => 'required|email',
            'password' => 'required|string|min:6|max:50'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        //Request is validated
        //Crean token
        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                 'success' => false,
                 'message' => 'Login credentials are invalid.',
                ], 400);
            }
        } catch (JWTException $e) {
    return $credentials;
        return response()->json([
            'success' => false,
            'message' => 'Could not create token.',
            ], 500);
        }
  
   //Token created, return with success response and jwt token
        return response()->json([
            'success' => true,
            'token' => $token,
        ]);
    }
    
    public function sendEmail(Request $request){ //function to send reset email
        if(!$this->validateEmail($request->email)){ //validates email
            return $this->failedResponse();
        }
        $this->send($request->email);
        return $this->successResponse();
    }
    public function send($email){
        $token = $this->createToken($email);
        Mail::to($email)->send(new SendMailreset($token, $email)); //token to send mail
    }
    public function createToken($email){ // function to get request mail
        $oldToken = DB::table('password_reset_tokens')->where('email', $email)->first();
        if($oldToken){
            return $oldToken->token;
        }
        //$token = str_random(60);
        $token = Str::random(40);
        $this->saveToken($token, $email);
        return $token;
    }
    public function saveToken($token, $email){ // saves new password
        DB::table('password_reset_tokens')->insert([
            'email' => $email,
            'token' => $token,
            'created_at' => Carbon::now()
        ]);
    }
    public function validateEmail($email){ // function to get mail from database
        return !!User::where('email', $email)->first();
    }
    public function failedResponse(){
        return response()->json([
            'error' => 'Email isn\t found on our database'
        ], Response::HTTP_NOT_FOUND);
    }
    public function successResponse(){
        return response()->json([
            'data' => 'Reset email sent successfully, please check your inbox.'
        ], Response::HTTP_OK);
    }

    public function passwordResetProcess(UpdatePasswordRequest $request){
        return $this->updatePasswordRow($request)->count() > 0 ? $this->resetPassword($request) : $this->tokenNotFoundError();
    }

    // verify if token is valid
    private function updatePasswordRow($request){
        return DB::table('password_reset_tokens')->where([
            'email' => $request->email,
            'token' => $request->resetToken
        ]);
    }

    // token not found response
    private function tokenNotFoundError(){
        return response()->json([
            'error' => 'Your email or token is wrong'
        ], Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    // reset password
    private function resetPassword($request){
        // find email
        $userData = User::whereEmail($request->email)->first();
        // update password
        $userData->update([
            'password' => bcrypt($request->password)
        ]);
        // remove verification data from database
        $this->updatePasswordRow($request)->delete();

        // reset password response
        return response()->json([
            'data' => 'Password has been updated'
        ], Response::HTTP_CREATED);
    }
    public function logout(Request $request)
    {
        //valid credential
        $validator = Validator::make($request->only('token'), [
            'token' => 'required'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

  //Request is validated, do logout        
        try {
            JWTAuth::invalidate($request->token);
 
            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
 
    public function get_user(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);
 
        $user = JWTAuth::authenticate($request->token);
 
        return response()->json(['user' => $user]);
    }
}