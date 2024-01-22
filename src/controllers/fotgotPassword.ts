import { PrismaClient } from "@prisma/client";
import eventEmitter from "events";
import nodemailer from "nodemailer";
import { Request, Response } from "express";
import bcrypt from "bcrypt";
const emitter = new eventEmitter();
const prisma = new PrismaClient();

var transport = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: process.env.AUTH_USER,
    pass: process.env.AUTH_PASS,
  },
});

const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });

    if (!existingUser) {
      return res.status(409).json({ message: "User not Found" });
    }

    const creatOTP = await prisma.otp.create({
      data: {
        otp: generateOTP(),
        expiredAt: new Date(new Date().getTime() + 5 * 60 * 1000),
        user: {
          connect: {
            email,
          },
        },
      },
      include: {
        user: true,
      },
    });

    // Send OTP to user's email
    emitter.emit("sendOTP", creatOTP.user.email, creatOTP.otp);

    return res
      .status(200)
      .json({
        verified: existingUser.verify,
        message: "Plz check your mail for OTP to reset password",
      });
  } catch (error) {
    return res.status(500).json({ message: "Something Went Wrong" });
  }
};

const generateOTP = () => {
  // Generate a 6-digit OTP
  return Math.floor(100000 + Math.random() * 900000);
};

emitter.on("sendOTP", (email, otp) => {
  const mailOptions = {
    from: process.env.AUTH_USER,
    to: email,
    subject: "Your OTP for Email Verification",
    text: `Your OTP is: ${otp}`,
  };

  transport.sendMail(mailOptions);
});

const verifyResetPasswordOTP = async (req: Request, res: Response) => {
  try {
    const { email, otp, password } = req.body;

    // Find the user with the provided email
    const user = await prisma.user.findUnique({
      where: { email },
      include: { otp: true }, // Include related OTP data
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Find the latest unexpired OTP for the user
    const latestOTP = user.otp.find(
      (otpData) => otpData.otp === otp && !isExpired(otpData.expiredAt)
    );

    if (!latestOTP) {
      return res.status(401).json({ message: "Invalid OTP" });
    }

    // Mark the user as verified or perform any other necessary actions
    // For example: await prisma.user.update({ where: { id: user.id }, data: { isVerified: true } });
    const hashedPassword = await bcrypt.hash(password, 10);
    const resetPassword = await prisma.user.update({
      data: {
        password: hashedPassword,
      },
      where: {
        email,
      },
    });

    return res
      .status(200)
      .json({
        verified: resetPassword.verify,
        message: "Password Successfully reset",
      });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Something Went Wrong" });
  }
};

const isExpired = (date: Date) => new Date() > new Date(date);

export { forgotPassword, verifyResetPasswordOTP };
