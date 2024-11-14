import { Strategy, VerifyCallback } from "passport-google-oauth2";
import passport, { Profile } from "passport";
import { NextFunction, Request, Response, Router } from "express";
import { config } from "../../../config";
import { createTokenSetCookie } from "../../../utils/jwt";
import { InsertExternalUserModel, NewUserPayload, SafeUser, SelectUserModel } from "../models/auth";
import { BadRequestError } from "../../../errors";

// Configure the Google OAuth strategy
passport.use(
  new Strategy(
    {
      clientID: config.GOOGLE_OAUTH.GOOGLE_CLIENT_ID,
      clientSecret: config.GOOGLE_OAUTH.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:4000/api/auth/signup/google/callback", // Make sure the URL matches
      passReqToCallback: true,
    },
    async (req: Request, accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => {
      // Log the user profile and email on successful login
      try {
        const newUserPayload: NewUserPayload = {
          email: profile.emails?.find((e) => e.type === "account")?.value,
          firstName: profile.name?.givenName,
          lastName: profile.name?.familyName,
          provider: "google",
        };
        if (newUserPayload.email) {
          const isUserExists = await SelectUserModel(newUserPayload.email);
          if (isUserExists && isUserExists.isVerified) {
            // only if user with this email is register and verified throw user exists error
            throw BadRequestError([{ message: `User with email ${newUserPayload.email} already exists`, field: "email" }]);
          }
        }
        const safeUser = await InsertExternalUserModel(newUserPayload);

        createTokenSetCookie(safeUser, req);
        return done(null, safeUser);
      } catch (err) {
        return done(err);
      }
    }
  )
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

    // Optionally, you can set the token as an HTTP-only cookie (for client-side use)

    // Respond with user data and JWT token
    res.send(userData);
  })(req, res, next);
});

// Success route
router.get("/auth/google/success", (req: Request, res: Response) => {
  if (req.user) {
    // Successfully authenticated, log the user info
    console.log("Authentication Successful!");
    console.log("User Profile:", req.user); // Log the entire user profile
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
