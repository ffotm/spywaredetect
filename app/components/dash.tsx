'use client'
import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Activity, Search, Clock, Zap, Database } from 'lucide-react';
import { pid } from 'process';

export default function AntispywareDashboard() {
    const [threats, setThreats] = useState([]);
    const [safeCount, setSafeCount] = useState(0);
    const [totalProcesses, setTotalProcesses] = useState(0);
    const [isScanning, setIsScanning] = useState(false);
    const [lastScanTime, setLastScanTime] = useState("Never");
    const [scanProgress, setScanProgress] = useState(0);
    const [error, setError] = useState(null);
    const [safe, setSafe] = useState(0);
    const [runningProcesses, setRunningProcesses] = useState([]);

    const fetchScan = async () => {
        try {
            setError(null);
            const response = await fetch('http://localhost:8000/scan');

            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }

            const data = await response.json();
            console.log("Scan data received:", data);

            setThreats(data.alerts || []);
            setTotalProcesses(data.total_processes || 0);
            setSafeCount(data.safe?.length || 0);
            setRunningProcesses(data.processes || []);

            const date = new Date();
            setLastScanTime(date.toLocaleTimeString());

        } catch (err) {
            console.error("Scan error:", err);
            setError(err.message);
        }
    };

    const startScan = async () => {
        setIsScanning(true);
        setScanProgress(0);
        streamScan();

        // Simulate progress bar
        const progressInterval = setInterval(() => {
            setScanProgress(prev => {
                if (prev >= 90) {
                    clearInterval(progressInterval);
                    return 90;
                }
                return prev + 10;
            });
        }, 200);

        await fetchScan();

        clearInterval(progressInterval);
        setScanProgress(100);

        setTimeout(() => {
            setIsScanning(false);
            setScanProgress(0);
        }, 500);
    };

    // Auto-refresh every 10 seconds when active
    useEffect(() => {
        if (isScanning) return;

        const interval = setInterval(fetchScan, 10000);
        return () => clearInterval(interval);
    }, [isScanning]);


    const streamScan = async () => {
        try {
            setError(null);
            const source = new EventSource('http://localhost:8000/scan/stream');
            source.onmessage = (e) => {
                const data = JSON.parse(e.data);
                console.log("Streaming scan data:", data);
                if (data.status === 'streaming') {
                    setRunningProcesses(prev => [
                        ...prev,
                        {
                            pid: data.data.PID,
                            name: data.data.Name,
                            path: data.data.Path,
                            memory: data.data.Memory
                        }
                    ]);
                    setTotalProcesses(prev => prev + 1);
                }
                else { source.close(); }

            };
            source.onerror = (e) => {
                source.close();
            }
        } catch (err) {
            console.error("Streaming scan error:", err);
        }
    }



    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'critical': return 'bg-red-900/30 text-red-400 border-red-500/50';
            case 'high': return 'bg-orange-900/30 text-orange-400 border-orange-500/50';
            case 'medium': return 'bg-yellow-900/30 text-yellow-400 border-yellow-500/50';
            default: return 'bg-blue-900/30 text-blue-400 border-blue-500/50';
        }
    };

    return (
        <div className="min-h-screen bg-gray-950 text-gray-100 p-8">
            <div className="max-w-7xl mx-auto space-y-6">

                {/* Header */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <Shield className="w-10 h-10 text-blue-400" />
                        <div>
                            <h1 className="text-3xl font-bold text-white">Malware Detector</h1>
                            <p className="text-sm text-gray-400">Process Monitor & Threat Detection</p>
                        </div>
                    </div>

                    <button
                        onClick={startScan}
                        disabled={isScanning}
                        className="flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg font-semibold transition-colors"
                    >
                        <Search className="w-5 h-5" />
                        {isScanning ? 'Scanning...' : 'Scan Now'}
                    </button>
                </div>

                {/* Error Display */}
                {error && (
                    <div className="bg-red-900/20 border border-red-500/50 rounded-lg p-4 text-red-400">
                        <strong>Error:</strong> {error}
                    </div>
                )}

                {/* Stats Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <StatCard
                        icon={Database}
                        label="Total Processes"
                        value={totalProcesses}
                        color="blue"
                    />
                    <StatCard
                        icon={AlertTriangle}
                        label="Threats Detected"
                        value={threats.length}
                        color="red"
                    />
                    <StatCard
                        icon={Shield}
                        label="Safe Processes"
                        value={safeCount}
                        color="green"
                    />
                    <StatCard
                        icon={Clock}
                        label="Last Scan"
                        value={lastScanTime}
                        color="purple"
                        small
                    />
                </div>

                {/* Scanning Progress */}
                {isScanning && (
                    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-sm text-gray-300">Scanning processes...</span>
                            <span className="text-sm font-mono text-blue-400">{scanProgress}%</span>
                        </div>
                        <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
                                style={{ width: `${scanProgress}%` }}
                            />
                        </div>
                    </div>
                )}

                {/* Threats List */}


                <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                    <div className="p-6 border-b border-gray-800">
                        <h2 className="text-xl font-bold flex items-center gap-2">
                            <AlertTriangle className="w-6 h-6 text-red-400" />
                            Detected Threats
                            <span className="ml-auto text-sm text-gray-400">{threats.length} items</span>
                        </h2>
                    </div>
                    {isScanning && (
                        <div className="p-4 border-b border-gray-800">
                            <h3 className="text-sm text-blue-400 mb-3 flex items-center gap-2">
                                <Activity className="w-4 h-4 animate-pulse" />
                                Scanning running processes
                            </h3>

                            <div className="max-h-60 overflow-y-auto space-y-2 font-mono text-sm">
                                {runningProcesses.map((p) => (
                                    <div
                                        key={`${p.pid}-${p.name}`}
                                        className="flex justify-between bg-gray-800/40 px-3 py-2 rounded"
                                    >
                                        <span className="truncate w-200">

                                            {p.path || 'Unknown'} (PID {p.pid})
                                        </span>

                                        <span className="text-gray-400">
                                            {p.memory}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <div className="divide-y divide-gray-800">
                        {threats.length === 0 ? (
                            <div className="p-12 text-center">
                                <Shield className="w-16 h-16 text-green-400 mx-auto mb-4 opacity-50" />
                                <p className="text-gray-400">No threats detected. Your system is clean!</p>
                                <p className="text-sm text-gray-500 mt-2">Click "Scan Now" to check for threats</p>
                            </div>
                        ) : (
                            threats.map((threat) => (
                                <div
                                    key={threat.id}
                                    className="p-4 hover:bg-gray-800/50 transition-colors"
                                >
                                    <div className="flex items-start justify-between gap-4">
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2 mb-2">
                                                <span className={`px-2 py-1 text-xs font-semibold rounded border ${getSeverityColor(threat.severity)} uppercase`}>
                                                    {threat.severity}
                                                </span>
                                                <span className="font-semibold text-white">{threat.name}</span>
                                                <span className="text-gray-500 text-sm">PID: {threat.pid}</span>
                                            </div>

                                            <p className="text-sm text-gray-400 font-mono truncate mb-2">
                                                {threat.path}
                                            </p>

                                            <div className="flex items-center gap-3 text-xs text-gray-500">
                                                <span>Detected: {threat.time}</span>
                                                <span>•</span>
                                                <span>Reasons: {threat.reasons.join(', ')}</span>
                                            </div>
                                        </div>

                                        <div className="flex items-center gap-2">
                                            <span className="text-2xl font-bold text-red-400">
                                                {threat.score}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Footer Info */}
                <div className="text-center text-sm text-gray-500">
                    Auto-refreshing every 10 seconds • Detection threshold: Score ≥ 2
                </div>
            </div>
        </div>
    );
}

function StatCard({ icon: Icon, label, value, color, small = false }) {
    const colors = {
        blue: 'from-blue-900/50 to-blue-800/50 border-blue-700/50',
        red: 'from-red-900/50 to-red-800/50 border-red-700/50',
        green: 'from-green-900/50 to-green-800/50 border-green-700/50',
        purple: 'from-purple-900/50 to-purple-800/50 border-purple-700/50',
    };

    const iconColors = {
        blue: 'text-blue-400',
        red: 'text-red-400',
        green: 'text-green-400',
        purple: 'text-purple-400',
    };

    return (
        <div className={`bg-gradient-to-br ${colors[color]} border rounded-lg p-5`}>
            <div className="flex items-center gap-3 mb-2">
                <Icon className={`w-5 h-5 ${iconColors[color]}`} />
                <span className="text-sm text-gray-400">{label}</span>
            </div>
            <div className={`${small ? 'text-lg' : 'text-3xl'} font-bold text-white`}>
                {value}
            </div>
        </div>
    );
}