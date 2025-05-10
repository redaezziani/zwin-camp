import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { MailService } from '../mail/mail.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as bcrypt from 'bcrypt';
import { TokenType, User } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import { addDays, addHours } from 'date-fns';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async signup(signupDto: SignupDto): Promise<{ message: string }> {
    const { email, password, name } = signupDto;

    // Check if user already exists
    const userExists = await this.prisma.user.findUnique({
      where: { email },
    });

    if (userExists) {
      throw new ConflictException('Email already in use');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user
    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
    });

    // Create verification token
    const verificationToken = uuidv4();
    const tokenExpires = addDays(new Date(), 1); // Token expires after 24 hours

    await this.prisma.token.create({
      data: {
        token: verificationToken,
        type: TokenType.EMAIL_VERIFICATION,
        expires: tokenExpires,
        userId: user.id,
      },
    });

    // Send verification email
    await this.mailService.sendVerificationEmail(email, verificationToken);

    return {
      message: 'User registered successfully. Please check your email to verify your account.',
    };
  }

  async login(loginDto: LoginDto): Promise<{ accessToken: string; user: Omit<User, 'password'> }> {
    const { email, password } = loginDto;

    // Find the user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      throw new UnauthorizedException('Please verify your email before logging in');
    }

    // Generate JWT token
    const payload = { sub: user.id, email: user.email };
    const accessToken = this.jwtService.sign(payload);

    // Remove password from user object
    const { password: _, ...userWithoutPassword } = user;

    return {
      accessToken,
      user: userWithoutPassword,
    };
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    // Find token in database
    const verificationToken = await this.prisma.token.findUnique({
      where: { token },
      include: { user: true },
    });

    // Check if token exists
    if (!verificationToken) {
      throw new BadRequestException('Invalid verification token');
    }

    // Check if token is correct type
    if (verificationToken.type !== TokenType.EMAIL_VERIFICATION) {
      throw new BadRequestException('Invalid token type');
    }

    // Check if token is expired
    if (verificationToken.expires < new Date()) {
      throw new BadRequestException('Token has expired');
    }

    // Verify user's email
    await this.prisma.user.update({
      where: { id: verificationToken.userId },
      data: { isEmailVerified: true },
    });

    // Delete the token
    await this.prisma.token.delete({
      where: { id: verificationToken.id },
    });

    return {
      message: 'Email verified successfully. You can now login.',
    };
  }

  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    // Find the user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    // Delete any existing verification tokens
    await this.prisma.token.deleteMany({
      where: {
        userId: user.id,
        type: TokenType.EMAIL_VERIFICATION,
      },
    });

    // Create a new verification token
    const verificationToken = uuidv4();
    const tokenExpires = addDays(new Date(), 1);

    await this.prisma.token.create({
      data: {
        token: verificationToken,
        type: TokenType.EMAIL_VERIFICATION,
        expires: tokenExpires,
        userId: user.id,
      },
    });

    // Send verification email
    await this.mailService.sendVerificationEmail(email, verificationToken);

    return {
      message: 'Verification email sent successfully',
    };
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<{ message: string }> {
    const { email } = forgotPasswordDto;

    // Find the user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      // For security reasons, we don't want to reveal that the email doesn't exist
      return {
        message: 'If your email is registered, you will receive a password reset link',
      };
    }

    // Delete any existing password reset tokens
    await this.prisma.token.deleteMany({
      where: {
        userId: user.id,
        type: TokenType.PASSWORD_RESET,
      },
    });

    // Create a password reset token
    const resetToken = uuidv4();
    const tokenExpires = addHours(new Date(), 1); // Token expires after 1 hour

    await this.prisma.token.create({
      data: {
        token: resetToken,
        type: TokenType.PASSWORD_RESET,
        expires: tokenExpires,
        userId: user.id,
      },
    });

    // Send password reset email
    await this.mailService.sendPasswordResetEmail(email, resetToken);

    return {
      message: 'If your email is registered, you will receive a password reset link',
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    const { token, password } = resetPasswordDto;

    // Find token in database
    const resetToken = await this.prisma.token.findUnique({
      where: { token },
      include: { user: true },
    });

    // Check if token exists
    if (!resetToken) {
      throw new BadRequestException('Invalid reset token');
    }

    // Check if token is correct type
    if (resetToken.type !== TokenType.PASSWORD_RESET) {
      throw new BadRequestException('Invalid token type');
    }

    // Check if token is expired
    if (resetToken.expires < new Date()) {
      throw new BadRequestException('Token has expired');
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user's password
    await this.prisma.user.update({
      where: { id: resetToken.userId },
      data: { password: hashedPassword },
    });

    // Delete the token
    await this.prisma.token.delete({
      where: { id: resetToken.id },
    });

    return {
      message: 'Password reset successfully',
    };
  }

  async getUserProfile(userId: string): Promise<Omit<User, 'password'>> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Remove password from user object
    const { password: _, ...userWithoutPassword } = user;

    return userWithoutPassword;
  }
}