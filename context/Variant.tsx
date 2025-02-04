"use client";

import {
  createContext,
  Dispatch,
  SetStateAction,
  useContext,
  useState,
} from "react";

interface VariantContextType {
  variant: string;
  setVariant: Dispatch<SetStateAction<string>>;
}

const VariantContext = createContext<VariantContextType | undefined>(undefined);

type Props = { children: React.ReactNode };

export const useVariant = () => {
  const context = useContext(VariantContext);

  if (!context) {
    throw new Error("useVariant must be used within a VariantProvider");
  }

  return context;
};

function Variant({ children }: Props) {
  const [variant, setVariant] = useState("home");
  const contextValue = { variant, setVariant };

  return (
    <>
      <VariantContext.Provider value={contextValue}>
        {children}
      </VariantContext.Provider>
    </>
  );
}

export default Variant;
