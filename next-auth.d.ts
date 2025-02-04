import NextAuth, { DefaultSession, DefaultUser, DefaultJWT } from "next-auth";

declare module "next-auth" {
  interface User {
    id: string;
    firstName: string;
    lastName: string;
    email: string;
    username: string;
    createdAt: string;
    accounts: any[];
  }

  interface Session {
    user: {
      id: string;
      firstName: string;
      lastName: string;
      email: string;
      username: string;
      createdAt: string;
      accounts: any[];
    } & DefaultSession["user"];
  }
}

declare module "next-auth/jwt" {
  interface JWT extends DefaultJWT {
    id: string;
    firstName: string;
    lastName: string;
    email: string;
    username: string;
    createdAt: string;
    accounts: any[];
  }
}
