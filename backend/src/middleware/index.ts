import { Request, Response, NextFunction } from 'express';
import store from '../models';
import { formatError } from '../utils/responseFormatter';

export const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json(formatError('UNAUTHORIZED', 'No token provided'));
    }

    const session = await store.getSessionByToken(token);
    if (!session || new Date() > new Date(session.expiresAt)) {
      return res.status(401).json(formatError('UNAUTHORIZED', 'Invalid or expired session'));
    }

    // Add user to request object
    req.user = { email: session.email };
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json(formatError('INTERNAL_SERVER_ERROR', 'Authentication failed'));
  }
};

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json(formatError('INTERNAL_SERVER_ERROR', 'Something went wrong'));
};
