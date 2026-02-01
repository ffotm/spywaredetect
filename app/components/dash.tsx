'use client'
import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Activity, Search, Trash2, Settings, FileWarning, Clock, TrendingUp, Zap, ChevronRight, Database, Cpu, HardDrive } from 'lucide-react';

export default function AntispywareDashboard() {
    const [activeScans, setActiveScans] = useState(0);
    const [threats, setThreats] = useState([
        { id: 1, name: 'Keylogger.Win32.Agent', severity: 'critical', path: 'C:\\Users\\AppData\\temp\\malware.exe', time: '2 min ago', status: 'quarantined' },
        { id: 2, name: 'Spyware.Generic.Tracker', severity: 'high', path: 'C:\\Program Files\\Unknown\\tracker.dll', time: '15 min ago', status: 'detected' },
        { id: 3, name: 'Adware.Browser.Extension', severity: 'medium', path: 'C:\\Users\\Extensions\\ad-inject.js', time: '1 hour ago', status: 'quarantined' },
    ]);
    const [scanProgress, setScanProgress] = useState(0);
    const [isScanning, setIsScanning] = useState(false);

    useEffect(() => {
        if (isScanning) {
            const interval = setInterval(() => {
                setScanProgress(prev => {
                    if (prev >= 100) {
                        setIsScanning(false);
                        return 0;
                    }
                    return prev + 2;
                });
            }, 100);
            return () => clearInterval(interval);
        }
    }, [isScanning]);

    const startScan = () => {
        setIsScanning(true);
        setScanProgress(0);
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'critical': return 'bg-red-500/10 text-red-400 border-red-500/30';
            case 'high': return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
            case 'medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
            default: return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
        }
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100 font-['JetBrains_Mono',_monospace] relative overflow-hidden">
            {/* Animated background grid */}
            <div className="fixed inset-0 opacity-20">
                <div className="absolute inset-0" style={{
                    backgroundImage: `
            linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)
          `,
                    backgroundSize: '50px 50px',
                    animation: 'gridScroll 20s linear infinite'
                }}></div>
            </div>

            {/* Glow effects */}
            <div className="fixed top-20 left-20 w-96 h-96 bg-blue-500/20 rounded-full blur-[100px] animate-pulse"></div>
            <div className="fixed bottom-20 right-20 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] animate-pulse" style={{ animationDelay: '1s' }}></div>

            <style>{`
        @keyframes gridScroll {
          0% { transform: translateY(0); }
          100% { transform: translateY(50px); }
        }
        @keyframes scan {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(10px); }
        }
        @keyframes pulse-glow {
          0%, 100% { box-shadow: 0 0 20px rgba(59, 130, 246, 0.3); }
          50% { box-shadow: 0 0 40px rgba(59, 130, 246, 0.6); }
        }
        .scan-line {
          animation: scan 2s ease-in-out infinite;
        }
        .glow-border {
          animation: pulse-glow 2s ease-in-out infinite;
        }
      `}</style>

            <div className="relative z-10 max-w-[1600px] mx-auto p-8">
                {/* Header */}
                <header className="mb-12 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <div className="relative">
                            <Shield className="w-12 h-12 text-blue-400" strokeWidth={1.5} />
                            <div className="absolute inset-0 bg-blue-500/30 blur-xl"></div>
                        </div>
                        <div>
                            <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-400 bg-clip-text text-transparent tracking-tight">
                                SENTINEL GUARD
                            </h1>
                            <p className="text-sm text-gray-500 mt-1 tracking-wide">Advanced Threat Protection System</p>
                        </div>
                    </div>
                    <div className="flex gap-4">
                        <button className="px-4 py-2 bg-gray-800/50 hover:bg-gray-700/50 border border-gray-700 rounded-lg transition-all duration-300 flex items-center gap-2">
                            <Settings className="w-4 h-4" />
                            Settings
                        </button>
                    </div>
                </header>

                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <StatCard
                        icon={Shield}
                        label="Protection Status"
                        value="ACTIVE"
                        trend="+100%"
                        color="blue"
                    />
                    <StatCard
                        icon={AlertTriangle}
                        label="Threats Blocked"
                        value="1,247"
                        trend="+23 today"
                        color="red"
                    />
                    <StatCard
                        icon={Activity}
                        label="Active Monitoring"
                        value="Real-time"
                        trend="24/7"
                        color="cyan"
                    />
                    <StatCard
                        icon={Clock}
                        label="Last Scan"
                        value="2 hrs ago"
                        trend="Scheduled"
                        color="emerald"
                    />
                </div>

                {/* Main Content Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Scanner Section */}
                    <div className="lg:col-span-2 space-y-6">
                        {/* Quick Scan Card */}
                        <div className="bg-gradient-to-br from-gray-900/90 via-gray-900/70 to-gray-900/90 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-8 relative overflow-hidden">
                            <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl"></div>

                            <div className="relative z-10">
                                <div className="flex items-center justify-between mb-6">
                                    <h2 className="text-xl font-bold flex items-center gap-3">
                                        <Search className="w-6 h-6 text-blue-400" />
                                        System Scanner
                                    </h2>
                                    <div className="flex gap-2">
                                        <button className="px-3 py-1.5 text-xs bg-gray-800/70 hover:bg-gray-700/70 border border-gray-700 rounded-lg transition-all">
                                            Quick
                                        </button>
                                        <button className="px-3 py-1.5 text-xs bg-gray-800/70 hover:bg-gray-700/70 border border-gray-700 rounded-lg transition-all">
                                            Deep
                                        </button>
                                        <button className="px-3 py-1.5 text-xs bg-gray-800/70 hover:bg-gray-700/70 border border-gray-700 rounded-lg transition-all">
                                            Custom
                                        </button>
                                    </div>
                                </div>

                                {isScanning ? (
                                    <div className="space-y-4">
                                        <div className="flex items-center justify-between text-sm">
                                            <span className="text-gray-400">Scanning system files...</span>
                                            <span className="text-blue-400 font-mono">{scanProgress}%</span>
                                        </div>
                                        <div className="relative h-3 bg-gray-800/50 rounded-full overflow-hidden border border-gray-700/50">
                                            <div
                                                className="absolute inset-y-0 left-0 bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300 rounded-full"
                                                style={{ width: `${scanProgress}%` }}
                                            >
                                                <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-3 gap-4 mt-6">
                                            <ScanStat icon={Database} label="Files Scanned" value="24,567" />
                                            <ScanStat icon={Cpu} label="CPU Usage" value="23%" />
                                            <ScanStat icon={HardDrive} label="Memory" value="1.2 GB" />
                                        </div>
                                    </div>
                                ) : (
                                    <div className="text-center py-12">
                                        <div className="inline-block mb-6 relative scan-line">
                                            <div className="w-24 h-24 rounded-full bg-gradient-to-br from-blue-500/20 to-cyan-500/20 flex items-center justify-center border border-blue-500/30">
                                                <Search className="w-12 h-12 text-blue-400" />
                                            </div>
                                            <div className="absolute inset-0 rounded-full bg-blue-500/20 blur-xl"></div>
                                        </div>
                                        <p className="text-gray-400 mb-6">Your system is protected. Run a scan to check for threats.</p>
                                        <button
                                            onClick={startScan}
                                            className="px-8 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 glow-border"
                                        >
                                            Start Quick Scan
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Threats Table */}
                        <div className="bg-gradient-to-br from-gray-900/90 via-gray-900/70 to-gray-900/90 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-6 overflow-hidden">
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-xl font-bold flex items-center gap-3">
                                    <FileWarning className="w-6 h-6 text-red-400" />
                                    Detected Threats
                                </h2>
                                <span className="text-sm text-gray-500">{threats.length} items</span>
                            </div>

                            <div className="space-y-3">
                                {threats.map((threat, index) => (
                                    <div
                                        key={threat.id}
                                        className="group bg-gray-800/30 hover:bg-gray-800/50 border border-gray-700/30 rounded-xl p-4 transition-all duration-300 cursor-pointer"
                                        style={{ animationDelay: `${index * 100}ms` }}
                                    >
                                        <div className="flex items-start justify-between">
                                            <div className="flex-1">
                                                <div className="flex items-center gap-3 mb-2">
                                                    <span className={`px-2 py-1 text-xs font-mono rounded-lg border ${getSeverityColor(threat.severity)} uppercase tracking-wider`}>
                                                        {threat.severity}
                                                    </span>
                                                    <span className="font-semibold text-gray-200">{threat.name}</span>
                                                </div>
                                                <p className="text-sm text-gray-500 font-mono mb-2">{threat.path}</p>
                                                <div className="flex items-center gap-4 text-xs text-gray-600">
                                                    <span className="flex items-center gap-1">
                                                        <Clock className="w-3 h-3" />
                                                        {threat.time}
                                                    </span>
                                                    <span className={`px-2 py-0.5 rounded ${threat.status === 'quarantined' ? 'bg-blue-500/10 text-blue-400' : 'bg-yellow-500/10 text-yellow-400'}`}>
                                                        {threat.status}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                <button className="p-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg transition-all">
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                                <button className="p-2 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 rounded-lg transition-all">
                                                    <ChevronRight className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Right Sidebar */}
                    <div className="space-y-6">
                        {/* System Health */}
                        <div className="bg-gradient-to-br from-gray-900/90 via-gray-900/70 to-gray-900/90 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-6">
                            <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                                <Activity className="w-5 h-5 text-emerald-400" />
                                System Health
                            </h3>
                            <div className="space-y-4">
                                <HealthItem label="Real-time Protection" status="active" value="100%" color="emerald" />
                                <HealthItem label="Firewall" status="active" value="100%" color="emerald" />
                                <HealthItem label="Web Protection" status="active" value="100%" color="emerald" />
                                <HealthItem label="Email Scanner" status="active" value="100%" color="blue" />
                            </div>
                        </div>

                        {/* Quick Actions */}
                        <div className="bg-gradient-to-br from-gray-900/90 via-gray-900/70 to-gray-900/90 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-6">
                            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                                <Zap className="w-5 h-5 text-yellow-400" />
                                Quick Actions
                            </h3>
                            <div className="space-y-2">
                                <ActionButton icon={Search} label="Full System Scan" />
                                <ActionButton icon={Shield} label="Update Definitions" />
                                <ActionButton icon={FileWarning} label="View Quarantine" />
                                <ActionButton icon={Settings} label="Configure Rules" />
                            </div>
                        </div>

                        {/* Recent Activity */}
                        <div className="bg-gradient-to-br from-gray-900/90 via-gray-900/70 to-gray-900/90 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-6">
                            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                                <Clock className="w-5 h-5 text-cyan-400" />
                                Activity Log
                            </h3>
                            <div className="space-y-3 text-sm">
                                <ActivityItem time="14:32" message="Threat blocked" type="success" />
                                <ActivityItem time="13:15" message="Scan completed" type="info" />
                                <ActivityItem time="12:08" message="Definitions updated" type="info" />
                                <ActivityItem time="11:45" message="Suspicious file detected" type="warning" />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

function StatCard({ icon: Icon, label, value, trend, color }) {
    const colors = {
        blue: 'from-blue-500/20 to-cyan-500/20 border-blue-500/30',
        red: 'from-red-500/20 to-orange-500/20 border-red-500/30',
        cyan: 'from-cyan-500/20 to-blue-500/20 border-cyan-500/30',
        emerald: 'from-emerald-500/20 to-green-500/20 border-emerald-500/30'
    };

    const iconColors = {
        blue: 'text-blue-400',
        red: 'text-red-400',
        cyan: 'text-cyan-400',
        emerald: 'text-emerald-400'
    };

    return (
        <div className={`bg-gradient-to-br ${colors[color]} backdrop-blur-xl border rounded-2xl p-6 relative overflow-hidden group hover:scale-105 transition-transform duration-300`}>
            <div className="absolute top-0 right-0 w-32 h-32 bg-white/5 rounded-full blur-2xl group-hover:bg-white/10 transition-all"></div>
            <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                    <Icon className={`w-8 h-8 ${iconColors[color]}`} strokeWidth={1.5} />
                    <TrendingUp className="w-4 h-4 text-gray-500" />
                </div>
                <div className="text-3xl font-bold mb-1 bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                    {value}
                </div>
                <div className="text-sm text-gray-400 mb-2">{label}</div>
                <div className="text-xs text-gray-500">{trend}</div>
            </div>
        </div>
    );
}

function ScanStat({ icon: Icon, label, value }) {
    return (
        <div className="text-center">
            <Icon className="w-6 h-6 text-blue-400 mx-auto mb-2" />
            <div className="text-lg font-bold text-gray-200">{value}</div>
            <div className="text-xs text-gray-500">{label}</div>
        </div>
    );
}

function HealthItem({ label, status, value, color }) {
    const colors = {
        emerald: 'bg-emerald-500',
        blue: 'bg-blue-500'
    };

    return (
        <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${colors[color]} animate-pulse`}></div>
                <span className="text-sm text-gray-300">{label}</span>
            </div>
            <span className="text-xs text-gray-500 font-mono">{value}</span>
        </div>
    );
}

function ActionButton({ icon: Icon, label }) {
    return (
        <button className="w-full flex items-center gap-3 px-4 py-3 bg-gray-800/30 hover:bg-gray-700/50 border border-gray-700/30 hover:border-gray-600/50 rounded-xl transition-all duration-300 group">
            <Icon className="w-4 h-4 text-gray-400 group-hover:text-blue-400 transition-colors" />
            <span className="text-sm text-gray-300 group-hover:text-gray-100 transition-colors">{label}</span>
            <ChevronRight className="w-4 h-4 ml-auto text-gray-600 group-hover:text-gray-400 transition-colors" />
        </button>
    );
}

function ActivityItem({ time, message, type }) {
    const colors = {
        success: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
        info: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
        warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    };

    return (
        <div className="flex items-start gap-3">
            <span className="text-xs text-gray-600 font-mono mt-1">{time}</span>
            <span className={`text-xs px-2 py-1 rounded border ${colors[type]}`}>{message}</span>
        </div>
    );
}