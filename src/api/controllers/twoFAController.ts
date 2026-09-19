import jwt from 'jsonwebtoken';
import {NextFunction, Request, Response} from 'express';
import {TOTP, Secret} from 'otpauth';
import encodeQR from '@paulmillr/qr';
import {LoginResponse, TwoFASetupResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {UserWithNoPassword} from '@sharedTypes/DBTypes';
import CustomError from '../../classes/CustomError';
import TwoFAModel from '../models/twoFAModel';

const AUTH_URL = process.env.AUTH_URL;

const setupTwoFA = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const {username, email, password} = req.body as {
      username?: string;
      email?: string;
      password?: string;
    };

    if (!username || !email || !password) {
      next(new CustomError('Username, email, and password are required', 400));
      return;
    }

    if (!AUTH_URL) {
      next(new CustomError('Auth API URL not configured', 500));
      return;
    }

    const authResponse = await fetch(`${AUTH_URL}/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        email,
        password,
      }),
    });

    const authData = (await authResponse.json()) as UserResponse;

    if (!authResponse.ok) {
      next(
        new CustomError(
          authData.message || 'Failed to create user with Auth API',
          authResponse.status,
        ),
      );
      return;
    }

    const userId = authData.user.user_id;

    const secret = new Secret({size: 32});
    const totp = new TOTP({
      issuer: 'MFA Starter',
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });

    const otpauthUri = totp.toString();
    const qrCodeSvg = encodeQR(otpauthUri, 'svg');

    const mfaRecord = await TwoFAModel.findOneAndUpdate(
      {email: email.toLowerCase()},
      {
        userId,
        email: email.toLowerCase(),
        twoFactorSecret: secret.base32,
        twoFactorEnabled: true,
        updatedAt: new Date(),
      },
      {upsert: true, new: true, setDefaultsOnInsert: true},
    );

    if (!mfaRecord) {
      next(new CustomError('MFA setup could not be completed', 500));
      return;
    }

    const response: TwoFASetupResponse = {
      message: 'MFA setup successful',
      qrCodeSvg,
      userId,
      email: email.toLowerCase(),
      enabled: true,
    };

    res.status(201).json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const verifyTwoFA = async (
  req: Request,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  const {email, code} = req.body as {email?: string; code?: string};

  try {
    if (!email || !code) {
      next(new CustomError('Email and code are required', 400));
      return;
    }

    const mfaRecord = await TwoFAModel.findOne({email: email.toLowerCase()});
    if (!mfaRecord) {
      next(new CustomError('Invalid credentials', 401));
      return;
    }

    const totp = new TOTP({
      issuer: 'MFA Starter',
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: mfaRecord.twoFactorSecret,
    });

    const validCode = totp.validate({
      token: String(code),
      window: 1,
    });

    if (validCode === null) {
      next(new CustomError('Invalid credentials', 401));
      return;
    }

    const userResponse = await fetch(`${AUTH_URL}/users/${mfaRecord.userId}`);
    if (!userResponse.ok) {
      next(new CustomError('User not found', 404));
      return;
    }

    const user = (await userResponse.json()) as UserWithNoPassword;

    if (!process.env.JWT_SECRET) {
      next(new CustomError('JWT secret not set', 500));
      return;
    }

    const token = jwt.sign(
      {
        user_id: user.user_id ?? mfaRecord.userId,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {expiresIn: '1h'},
    );

    const response: LoginResponse = {
      message: 'Login successful',
      token,
      user: {
      user_id: user.user_id,
      username: user.username,
      email: user.email,
      created_at: user.created_at,
      level_name: user.level_name,
      },
    };

    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
