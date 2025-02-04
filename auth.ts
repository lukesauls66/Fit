import NextAuth from "next-auth";
import Facebook from "next-auth/providers/facebook";
import Google from "next-auth/providers/google";
import Credentials from "next-auth/providers/credentials";
import prisma from "@/lib/prisma";
import { signInSchema } from "@/lib/zod";
import { compare } from "bcrypt";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { User } from "next-auth";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Google,
    Facebook,
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        passsword: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        const { email, password } = await signInSchema.parseAsync(credentials);

        const user = await prisma.user.findUnique({
          where: { email },
          include: { accounts: true },
        });

        if (!user || !user.hashedPassword) {
          throw new Error("Email does not exist");
        }

        const isPasswordValid = await compare(password, user.hashedPassword);

        if (!isPasswordValid) {
          throw new Error("Incorrect password");
        }

        if (user) {
          const userRes: User = {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            username: user.username,
            createdAt: user.createdAt.toISOString(),
            accounts: user.accounts,
          };

          return userRes;
        }

        return null;
      },
    }),
  ],
  debug: process.env.MODE_ENV === "development",
  adapter: PrismaAdapter(prisma),
  session: {
    strategy: "jwt",
  },
  secret: process.env.NEXTAUTH_SECRET,
  callbacks: {
    async signIn({ user, account }) {
      if (account?.provider && account?.provider !== "credentials") {
        const existingAccount = await prisma.account.findUnique({
          where: {
            provider_providerAccountId: {
              provider: account.provider,
              providerAccountId: account.providerAccountId,
            },
          },
        });

        if (existingAccount) {
          return true;
        }

        const existingUser = await prisma.user.findUnique({
          where: {
            email: user.email || "",
          },
        });

        if (existingUser) {
          await prisma.account.create({
            data: {
              userId: existingUser.id,
              type: "oauth",
              provider: account.provider,
              providerAccountId: account.providerAccountId,
              access_token: account.access_token,
              refresh_token: account.refresh_token,
              expires_at: account.expires_at,
              id_token: account.id_token || "",
              token_type: account.token_type,
            },
          });

          return true;
        } else {
          return "/?Variant=register";
        }
      }

      return true;
    },
    async jwt({ token, user }) {
      if (user) {
        const dbUser = await prisma.user.findUnique({
          where: { id: user.id },
          include: {
            accounts: {
              select: {
                id: true,
                userId: true,
                type: true,
                provider: true,
              },
            },
          },
        });

        if (dbUser) {
          token.id = dbUser.id;
          token.firstName = dbUser.firstName;
          token.lastName = dbUser.lastName;
          token.email = dbUser.email;
          token.username = dbUser.username;
          token.createdAt = dbUser.createdAt.toISOString();
          token.accounts = dbUser.accounts;
        }
      }

      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id as string;
        session.user.firstName = token.firstName as string;
        session.user.lastName = token.lastName as string;
        session.user.email = token.email as string;
        session.user.username = token.username as string;
        session.user.createdAt = token.createdAt as string;
        session.user.accounts = token.accounts as any[];
      }

      return session;
    },
  },
});
