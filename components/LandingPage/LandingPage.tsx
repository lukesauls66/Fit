"use client";

import LoginPage from "../LoginPage";
import SignupPage from "../SignupPage";
import HomePage from "../HomePage";
import { useVariant } from "@/context/Variant";
import { useEffect, useState } from "react";

const LandingPage = () => {
  const { variant, setVariant } = useVariant();
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  });

  useEffect(() => {
    if (isClient) {
      const updateVariant = () => {
        const queryParams = new URLSearchParams(window.location.search);
        const variantQuery = queryParams.get("Variant");

        if (variantQuery) {
          setVariant(variantQuery);
        }
      };

      updateVariant();

      const handlePopState = () => updateVariant();
      window.addEventListener("popstate", handlePopState);

      return () => {
        window.removeEventListener("popstate", handlePopState);
      };
    }
  }, [isClient, setVariant]);

  if (!isClient) {
    return null;
  }

  return (
    <div className="bg-[#e7e7e7] min-h-screen">
      {variant === "home" ? (
        <HomePage />
      ) : variant === "login" ? (
        <LoginPage />
      ) : (
        <SignupPage />
      )}
    </div>
  );
};

export default LandingPage;
