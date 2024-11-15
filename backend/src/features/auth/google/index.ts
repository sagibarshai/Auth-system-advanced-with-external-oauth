import { Strategy, StrategyOptionsWithRequest, VerifyCallback } from "passport-google-oauth2";
import passport, { Profile } from "passport";
import { NextFunction, Request, Response, Router } from "express";
import { config } from "../../../config";
import { createTokenSetCookie, deleteTokenCookie } from "../../../utils/jwt";
import { InsertExternalUserModel, NewUserPayload, SafeUser, SelectUserModel, UpdateLoginModel } from "../models/auth";
import { BadRequestError } from "../../../errors";
import { currentUserMiddleware } from "../../../middlewares/current-user.ts";

const GOOGLE_OAUTH_CONFIG: StrategyOptionsWithRequest = {
  clientID: config.GOOGLE_OAUTH.GOOGLE_CLIENT_ID,
  clientSecret: config.GOOGLE_OAUTH.GOOGLE_CLIENT_SECRET,
  callbackURL: config.GOOGLE_OAUTH.GOOGLE_CALLBACK_URL,
  passReqToCallback: true,
};

console.log("GOOGLE_OAUTH_CONFIG ", GOOGLE_OAUTH_CONFIG.callbackURL);

passport.use(
  new Strategy(GOOGLE_OAUTH_CONFIG, async (req: Request, accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => {
    deleteTokenCookie(req);

    const email = profile.emails?.find((e) => e.type === "account")?.value;

    if (!email) {
      // system not support sign up or sign in operations for users without email
      throw BadRequestError([
        {
          message: `We could not retrieve your email address from the provided information. Please ensure you have granted the necessary permissions or use an account with a valid email.`,
          field: "email",
        },
      ]);
    }

    try {
      const newUserPayload: NewUserPayload = {
        email,
        firstName: profile.name?.givenName,
        lastName: profile.name?.familyName,
        provider: "google",
      };

      const existingUser = await SelectUserModel(newUserPayload.email);

      if (existingUser) {
        // user with that email already register

        if (existingUser.provider === "app") {
          if (existingUser.isVerified) {
            throw BadRequestError([
              {
                message: `User with email ${newUserPayload.email} already exists and cannot register with google, Please sign in with email and password`,
                field: "email",
              },
            ]);
          } else {
            throw BadRequestError([
              {
                message: `User with email ${newUserPayload.email} already exists and cannot register with ${existingUser.provider}, Please verify your email and sign in with email and password`,
                field: "email",
              },
            ]);
          }
        }

        if (existingUser.provider === "google") {
          // User exists and the provider is google, sign him in and set token cookie
          const safeUser = await UpdateLoginModel(existingUser.email!);
          createTokenSetCookie(safeUser, req);
          return done(null, safeUser);
        }
      } else {
        // user not exists, sign him up ans set token cookie
        const safeUser = await InsertExternalUserModel(newUserPayload);
        createTokenSetCookie(safeUser, req);
        return done(null, safeUser);
      }
    } catch (err) {
      return done(err);
    }
  })
);

const router = Router();

// Route to initiate Google login
router.get("/signup/google", (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate("google", { scope: ["email", "profile"] })(req, res, next); // Call the passport.authenticate() function
});

// Callback route after successful Google login
router.get("/signup/google/callback", async (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate("google", { failureRedirect: "/auth/google/failure" }, (err: unknown, userData: SafeUser) => {
    console.log("err ", err);
    if (err) return next(err);

    res.send(userData);
  })(req, res, next);
});

// Success route
router.get("/auth/google/success", currentUserMiddleware, (req: Request, res: Response) => {
  if (req.user) {
    // Successfully authenticated, log the user info
    console.log("Authentication Successful!");
    console.log("User Profile:", req.currentUser); // Log the entire user profile
    res.send("Google Authentication Successful!"); // Send success message
  } else {
    res.send("No user data found."); // In case there's no user in session
  }
});

// Failure route
router.get("/auth/google/failure", (req: Request, res: Response) => {
  console.log("Google Authentication Failed.");
  res.send("Google Authentication Failed.");
});

export { router as GoogleRouter };
