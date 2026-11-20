import React from "react";

interface HeroBackgroundProps {
  children: React.ReactNode;
}

export function HeroBackground({ children }: HeroBackgroundProps) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-gradient-to-b from-[#E0F2FE] via-[#EFF9FF] to-white">
      {/* Faint upper-right sunshine glow */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-28 -right-28 h-[460px] w-[460px] rounded-full opacity-55 blur-3xl"
        style={{
          background:
            "radial-gradient(circle, rgba(251,191,36,0.34) 0%, rgba(254,243,199,0.22) 45%, rgba(239,249,255,0) 75%)",
        }}
      />

      {/* Subtle abstract cloud & flowing telemetry network SVG */}
      <svg
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 h-full w-full"
        viewBox="0 0 1440 900"
        preserveAspectRatio="xMidYMid slice"
        fill="none"
      >
        <defs>
          <linearGradient id="skyLineGrad" x1="0" y1="0" x2="1440" y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#38BDF8" stopOpacity="0" />
            <stop offset="30%" stopColor="#38BDF8" stopOpacity="0.22" />
            <stop offset="70%" stopColor="#0284C7" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#FBBF24" stopOpacity="0.2" />
          </linearGradient>
        </defs>

        {/* Soft cloud depth silhouettes */}
        <path
          d="M-60 640 C 180 560, 340 690, 560 620 C 780 550, 960 660, 1180 590 C 1320 545, 1410 570, 1500 540 L 1500 920 L -60 920 Z"
          fill="#FFFFFF"
          fillOpacity="0.55"
        />
        <path
          d="M-40 720 C 210 660, 420 755, 680 695 C 930 640, 1160 735, 1490 660 L 1490 920 L -40 920 Z"
          fill="#FFFFFF"
          fillOpacity="0.78"
        />

        {/* Flowing telemetry lines */}
        <path
          d="M-80 310 C 240 240, 460 390, 780 300 C 1060 220, 1250 320, 1520 230"
          stroke="url(#skyLineGrad)"
          strokeWidth="1.5"
        />
        <path
          d="M-80 355 C 280 295, 510 430, 820 345 C 1100 270, 1280 360, 1520 280"
          stroke="url(#skyLineGrad)"
          strokeWidth="1"
          strokeDasharray="6 6"
        />
        <circle cx="340" cy="316" r="3.5" fill="#38BDF8" fillOpacity="0.45" />
        <circle cx="780" cy="300" r="4" fill="#0284C7" fillOpacity="0.4" />
        <circle cx="1180" cy="272" r="3.5" fill="#FBBF24" fillOpacity="0.55" />
      </svg>

      <div className="relative z-10">{children}</div>
    </div>
  );
}
