import { Role } from './role';
export class Account {
    id?: number;     // string or number
    title?: string;
    firstName?: string;
    lastName?: string;
    email?: string;
    role?: Role;
    jwtToken?: string;
    dateCreated?: string;
    isVerified?: boolean;
    refreshTokens: string[];
    verificationToken?: string;
    password?: string;
    resetToken?: string; 
    resetTokenExpires?: string;

    constructor() {
        this.refreshTokens = []; 
    }
}