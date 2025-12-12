import { Request, Response } from 'express';
import store from '../models';
import emailService from '../utils/emailService';
import { generateOTP } from '../utils/helpers';
import { formatSuccess, formatError } from '../utils/responseFormatter';

class AuthController {
  static async sendOTP(req: Request, res: Response) {
    try {
      const { email } = req.body;

      // Validate email
      if (!email) {
        return res.status(400).json(formatError('INVALID_EMAIL', 'Email is required'));
      }

      // Generate OTP
      const otp = generateOTP(6);
      await store.saveOTP(email, otp, 10); // 10 minutes expiry

      // Send email
      await emailService.sendOTPEmail(email, otp);

      // Create or update user
      await store.createUser(email);

      res.json(formatSuccess({ message: 'OTP sent successfully' }));
    } catch (error) {
      console.error('Error in sendOTP:', error);
      res.status(500).json(formatError('INTERNAL_SERVER_ERROR', 'Failed to send OTP'));
    }
  }

  static async verifyOTP(req: Request, res: Response) {
    try

@"
import { Request, Response } from 'express';
import store from '../models';
import emailService from '../utils/emailService';
import { generateOTP } from '../utils/helpers';
import { formatSuccess, formatError } from '../utils/responseFormatter';

class AuthController {
  static async sendOTP(req: Request, res: Response) {
    try {
      const { email } = req.body;

      // Validate email
      if (!email) {
        return res.status(400).json(formatError('INVALID_EMAIL', 'Email is required'));
      }

      // Generate OTP
      const otp = generateOTP(6);
      await store.saveOTP(email, otp, 10); // 10 minutes expiry

      // Send email
      await emailService.sendOTPEmail(email, otp);

      // Create or update user
      await store.createUser(email);

      res.json(formatSuccess({ message: 'OTP sent successfully' }));
    } catch (error) {
      console.error('Error in sendOTP:', error);
      res.status(500).json(formatError('INTERNAL_SERVER_ERROR', 'Failed to send OTP'));
    }
  }

  static async verifyOTP(req: Request, res: Response) {
    try {
      const { email, otp } = req.body;

      // Verify OTP
      const isValid = await store.verifyOTP(email, otp);
      if (!isValid) {
        return res.status(400).json(formatError('INVALID_OTP', 'Invalid or expired OTP'));
      }

      // Create session
      const session = await store.createSession(
        email,
        24, // 24 hours expiry
        req.ip,
        req.headers['user-agent']
      );

      res.json(formatSuccess({
        token: session.token,
        expiresAt: session.expiresAt
      }));
    } catch (error) {
      console.error('Error in verifyOTP:', error);
      res.status(500).json(formatError('INTERNAL_SERVER_ERROR', 'Failed to verify OTP'));
    }
  }

  static async logout(req: Request, res: Response) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        await store.deleteSession(token);
      }
      res.json(formatSuccess({ message: 'Logged out successfully' }));
    } catch (error) {
      console.error('Error in logout:', error);
      res.status(500).json(formatError('INTERNAL_SERVER_ERROR', 'Failed to logout'));
    }
  }
}

export default AuthController;
