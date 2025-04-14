import { Role } from './role';

export interface Account {
    id: string;
    title?: string;
    firstName: string;
    lastName: string;
    email: string;
    role: string;
    isActive: boolean;
    isToggling?: boolean;
    jwtToken?: string;
    dateCreated?: string;
    isVerified?: boolean;
    refreshTokens: string[];
    verificationToken?: string;
    password?: string;
    resetToken?: string; 
    resetTokenExpires?: string;
}