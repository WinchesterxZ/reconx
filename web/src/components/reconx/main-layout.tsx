"use client";

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Plus,
  History,
  Terminal,
  Shield,
  ChevronLeft,
  ChevronRight,
  Menu,
} from "lucide-react";
import type { ViewMode } from "@/lib/reconx-types";

interface MainLayoutProps {
  activeView: ViewMode;
  onViewChange: (view: ViewMode) => void;
  children: React.ReactNode;
  runningScanId: string | null;
}

const navItems = [
  { id: "new-scan" as ViewMode, label: "New Scan", icon: Plus },
  { id: "history" as ViewMode, label: "Scan History", icon: History },
];

export default function MainLayout({
  activeView,
  onViewChange,
  children,
  runningScanId,
}: MainLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen flex bg-[#0a0c0f] text-gray-200">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed lg:static z-50 h-screen flex flex-col bg-[#0d1117] border-r border-emerald-900/30 transition-all duration-300 ${
          sidebarOpen ? "w-64" : "w-16"
        } ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 p-4 border-b border-emerald-900/30">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-emerald-500/10 shrink-0">
            <Shield className="w-5 h-5 text-[#00ff88]" />
          </div>
          {sidebarOpen && (
            <div className="overflow-hidden">
              <h1 className="text-lg font-bold tracking-tight text-white">
                Recon<span className="text-[#00ff88]">X</span>
              </h1>
              <p className="text-[10px] text-gray-500 -mt-0.5 tracking-widest uppercase">
                Bug Bounty Recon
              </p>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 p-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onViewChange(item.id);
                  setMobileOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? "bg-emerald-500/10 text-[#00ff88] shadow-sm shadow-emerald-500/5"
                    : "text-gray-400 hover:bg-white/5 hover:text-gray-200"
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? "text-[#00ff88]" : ""}`} />
                {sidebarOpen && <span>{item.label}</span>}
              </button>
            );
          })}

          {/* Running scan shortcut */}
          {runningScanId && (activeView !== "progress") && (
            <>
              <Separator className="my-3 bg-emerald-900/20" />
              <button
                onClick={() => {
                  onViewChange("progress");
                  setMobileOpen(false);
                }}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium bg-emerald-500/10 text-[#00ff88] animate-pulse"
              >
                <Terminal className="w-4 h-4 shrink-0" />
                {sidebarOpen && (
                  <span className="truncate">Active Scan</span>
                )}
              </button>
            </>
          )}
        </nav>

        {/* Collapse toggle */}
        <div className="p-2 border-t border-emerald-900/30 hidden lg:block">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="w-full flex items-center justify-center p-2 rounded-lg text-gray-500 hover:bg-white/5 hover:text-gray-300 transition-colors"
          >
            {sidebarOpen ? (
              <ChevronLeft className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Version */}
        {sidebarOpen && (
          <div className="px-4 pb-3">
            <p className="text-[10px] text-gray-600 font-mono">v1.0.0-beta</p>
          </div>
        )}
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-h-screen overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center gap-3 px-4 py-3 border-b border-white/5 bg-[#0d1117]/80 backdrop-blur-sm">
          <button
            onClick={() => setMobileOpen(true)}
            className="lg:hidden p-1.5 rounded-lg text-gray-400 hover:bg-white/5"
          >
            <Menu className="w-5 h-5" />
          </button>
          <div className="flex-1">
            <p className="text-sm text-gray-400">
              {activeView === "new-scan" && "Configure and launch a new reconnaissance scan"}
              {activeView === "history" && "View and manage past scan results"}
              {activeView === "progress" && "Monitor active scan progress in real-time"}
              {activeView === "results" && "Review scan findings and exported data"}
            </p>
          </div>
          {runningScanId && activeView !== "progress" && (
            <button
              onClick={() => onViewChange("progress")}
              className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 text-[#00ff88] text-xs font-medium border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
              Scan Running
            </button>
          )}
        </header>

        {/* Content */}
        <div className="flex-1 overflow-auto">
          <div className="p-4 md:p-6 max-w-7xl mx-auto w-full">
            {children}
          </div>
        </div>
      </main>
    </div>
  );
}
