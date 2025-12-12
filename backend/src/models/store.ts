import { v4 as uuidv4 } from 'uuid';

interface User {
  id: string;
  email: string;
  createdAt: Date;
}

interface OTPRecord {
  id: string;
  email: string;
  otp: string;
  createdAt: Date;
  expiresAt: Date;
  attempts: number;
  maxAttempts: number;
}

interface Session {
  id: string;
  userId: string;
  email: string;
  token: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

class InMemoryStore {
  private users: Map<string, User> = new Map();
  private sessions: Map<string, Session> = new Map();
  private otpRecords: Map<string, OTPRecord> = new Map();

  // User methods
  async getUserByEmail(email: string): Promise<User | null> {
    const normalizedEmail = email.toLowerCase().trim();
    for (const user of this.users.values()) {
      if (user.email === normalizedEmail) {
        return user;
      }
    }
    return null;
  }

  async createUser(email: string): Promise<User> {
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await this.getUserByEmail(normalizedEmail);
    if (existingUser) {
      return existingUser;
    }

    const user: User = {
      id: uuidv4(),
      email: normalizedEmail,
      createdAt: new Date(),
    };

    this.users.set(user.id, user);
    return user;
  }

  // OTP methods
  async saveOTP(email: string, otp: string, expiryMinutes: number): Promise<OTPRecord> {
    const normalizedEmail = email.toLowerCase().trim();
    const record: OTPRecord = {
      id: uuidv4(),
      email: normalizedEmail,
      otp,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + expiryMinutes * 60 * 1000),
      attempts: 0,
      maxAttempts: 5,
    };

    // Remove any existing OTPs for this email
    for (const [id, existing] of this.otpRecords.entries()) {
      if (existing.email === normalizedEmail) {
        this.otpRecords.delete(id);
      }
    }

    this.otpRecords.set(record.id, record);
    return record;
  }

  async getOTPByEmail(email: string): Promise<OTPRecord | null> {
    const normalizedEmail = email.toLowerCase().trim();
    for (const record of this.otpRecords.values()) {
      if (record.email === normalizedEmail && record.expiresAt > new Date()) {
        return record;
      }
    }
    return null;
  }

  async verifyOTP(email: string, otp: string): Promise<boolean> {
    const normalizedEmail = email.toLowerCase().trim();
    const record = await this.getOTPByEmail(normalizedEmail);
    
    if (!record) {
      return false;
    }

    if (record.attempts >= record.maxAttempts) {
      this.otpRecords.delete(record.id);
      return false;
    }

    if (record.otp === otp) {
      this.otpRecords.delete(record.id);
      return true;
    }

    record.attempts++;
    return false;
  }

  async deleteOTPByEmail(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    for (const [id, record] of this.otpRecords.entries()) {
      if (record.email === normalizedEmail) {
        this.otpRecords.delete(id);
      }
    }
  }

  // Session methods
  async createSession(
    userId: string,
    email: string,
    expiryHours: number,
    ipAddress?: string,
    userAgent?: string
  ): Promise<Session> {
    const session: Session = {
      id: uuidv4(),
      userId,
      email: email.toLowerCase().trim(),
      token: uuidv4(),
      expiresAt: new Date(Date.now() + expiryHours * 60 * 60 * 1000),
      ipAddress,
      userAgent,
    };

    this.sessions.set(session.id, session);
    return session;
  }

  async getSessionById(sessionId: string): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    if (!session || session.expiresAt < new Date()) {
      return null;
    }
    return session;
  }

  async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  async deleteAllSessionsByEmail(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    for (const [id, session] of this.sessions.entries()) {
      if (session.email === normalizedEmail) {
        this.sessions.delete(id);
      }
    }
  }

  // Cleanup expired records
  async cleanupExpiredRecords(): Promise<void> {
    const now = new Date();
    
    // Clean up expired OTPs
    for (const [id, record] of this.otpRecords.entries()) {
      if (record.expiresAt < now) {
        this.otpRecords.delete(id);
      }
    }

    // Clean up expired sessions
    for (const [id, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(id);
      }
    }
  }

  // Get statistics
  async getStats() {
    return {
      users: this.users.size,
      sessions: this.sessions.size,
      otpRecords: this.otpRecords.size,
    };
  }
}

// Create a singleton instance
const store = new InMemoryStore();

// Clean up expired records every hour
setInterval(() => {
  store.cleanupExpiredRecords().catch(console.error);
}, 60 * 60 * 1000);

export default store;
