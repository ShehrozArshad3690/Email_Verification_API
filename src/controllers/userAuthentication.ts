import { PrismaClient } from "@prisma/client";
import eventEmitter from "events";
import nodemailer from "nodemailer";
import { Request, Response } from "express";
import bcrypt from "bcrypt";
const emitter = new eventEmitter();
const prisma = new PrismaClient();

// createUser,loginUser
const createUser = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (email == "" || password == "") {
      return res
        .status(422)
        .json({ message: "Email and Password could not be empty" });
    } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      return res.status(403).json({ message: "Invalid Email" });
    } else if (password.length < 8) {
      return res
        .status(422)
        .json({ message: "Password must be 8 digits long" });
    } else {
      const existingUser = await prisma.user.findUnique({ where: { email } });

      if (existingUser) {
        return res.status(409).json({ message: "User Already Found" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const addUser = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          otp: {
            create: {
              otp: generateOTP(),
              expiredAt: new Date(new Date().getTime() + 5 * 60 * 1000), // OTP expiration time (5 minutes)
            },
          },
        },
        include: {
          otp: true,
        },
      });

      // Send OTP to user's email
      emitter.emit("sendOTP", email, addUser.otp[0].otp);

      return res.status(200).json({
        verified: addUser.verify,
        message: "User Registered Successfully",
      });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Something Went Wrong" });
  }
};

const generateOTP = () => {
  // Generate a 6-digit OTP
  return Math.floor(100000 + Math.random() * 900000);
};

var transport = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: process.env.AUTH_USER,
    pass: process.env.AUTH_PASS,
  },
});

emitter.on("sendOTP", (email: string, otp: number) => {
  const mailOptions = {
    from: process.env.AUTH_USER,
    to: email,
    subject: "Your OTP for Email Verification",
    text: `Your OTP is: ${otp}`,
  };
  transport.sendMail(mailOptions);
});

const verifySignupOTP = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;

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

    const verifyOTPStatus = await prisma.user.update({
      data: {
        verify: true,
      },
      where: {
        email,
      },
    });

    return res.status(200).json({
      verified: verifyOTPStatus.verify,
      message: "OTP verified successfully",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Something Went Wrong" });
  }
};

const isExpired = (date: Date) => new Date() > new Date(date);

const loginUser = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (email == "" || password == "") {
      return res
        .status(422)
        .json({ message: "Email and Password could not be empty" });
    } else {
      const existingUser = await prisma.user.findUnique({
        where: {
          email,
        },
      });
      if (!existingUser) {
        return res.status(404).json({ message: "Invalid Credentials" });
      }
      const foundPassword = await bcrypt.compare(
        password,
        existingUser.password
      );
      if (!foundPassword) {
        return res.status(404).json({ message: "Invalid Credentials" });
      } else if (existingUser.verify == false) {
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
        emitter.emit("sendOTP", creatOTP.user.email, creatOTP.otp);
      }
      return res
        .status(200)
        .json({ verified: existingUser.verify, message: "Login Successfull" });
    }
  } catch (error) {
    return res.status(500).json({ message: "Something Went Wrong" });
  }
};

export { createUser, loginUser, verifySignupOTP };
