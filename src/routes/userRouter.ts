import express from "express";
import {
  createUser,
  loginUser,
  verifySignupOTP,
} from "../controllers/userAuthentication";
import {
  forgotPassword,
  verifyResetPasswordOTP,
} from "../controllers/fotgotPassword";
const router = express.Router();

router.post("/signup", createUser);
router.put("/email/verify", verifySignupOTP);
router.post("/signin", loginUser);
router.post("/forgot-password", forgotPassword);
router.put("/reset-password", verifyResetPasswordOTP);

export { router };
