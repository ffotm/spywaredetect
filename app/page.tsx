import React from "react";
import "./globals.css";
import Dashboard from "./dashboard";


export default function Home() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <Dashboard />
    </div>
  );
}
