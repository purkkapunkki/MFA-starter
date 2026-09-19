type TwoFA = {
  userId: number;
  email: string;
  twoFactorSecret: string;
  twoFactorEnabled: boolean;
  createdAt?: Date;
  updatedAt?: Date;
};

export {TwoFA};
