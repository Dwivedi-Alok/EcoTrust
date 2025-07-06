import React, { useState } from 'react';
import { AlertTriangle, Shield, CheckCircle, XCircle, Globe, Lock, Eye, AlertCircle, FileText, Bot, Search, ExternalLink } from 'lucide-react';

export default function WebsiteSecurityChecker() {
    const [url, setUrl] = useState('');
    const [results, setResults] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    const suspiciousPatterns = [
        { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, name: 'IP Address Instead of Domain', risk: 'high' },
        { pattern: /[a-zA-Z0-9-]+\.(tk|ml|ga|cf)$/, name: 'Suspicious TLD', risk: 'medium' },
        { pattern: /[a-zA-Z0-9-]+\.(bit|onion)$/, name: 'Dark Web/Tor Domain', risk: 'high' },
        { pattern: /[0-9]{10,}/, name: 'Unusually Long Number Sequence', risk: 'medium' },
        { pattern: /[a-zA-Z0-9-]{30,}/, name: 'Unusually Long Domain Name', risk: 'medium' },
        { pattern: /[^a-zA-Z0-9.-]/, name: 'Special Characters in Domain', risk: 'high' },
        { pattern: /^https?:\/\/[^\/]*[a-zA-Z0-9-]+\.(com|org|net|edu|gov)-[a-zA-Z0-9-]+/, name: 'Suspicious Subdomain Pattern', risk: 'high' },
        { pattern: /paypal|amazon|google|microsoft|apple|facebook|twitter|instagram|linkedin|github/i, name: 'Potential Brand Impersonation', risk: 'high' },
        { pattern: /secure|login|verify|update|confirm|account/i, name: 'Phishing Keywords', risk: 'medium' },
        { pattern: /[0-9]+\.[a-z]{2,}\/[a-zA-Z0-9]{20,}/, name: 'Suspicious URL Structure', risk: 'medium' }
    ];

    const checkSSLCertificate = async (hostname) => {
        try {
            const response = await fetch('https://webscarping-x2tm.onrender.com/api/check-ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hostname }),
            });
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('SSL Check API error:', error);
            return { error: 'Could not connect to SSL analysis service.' };
        }
    };

    const analyzeUrl = async () => {
        if (!url.trim()) return;
        setIsAnalyzing(true);
        setResults(null);

        let localResults = performAnalysis(url);

        try {
            const hostname = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
            const sslResults = await checkSSLCertificate(hostname);

            if (!sslResults.error) {
                // Update risk score based on SSL certificate validity and backend risk assessment
                if (sslResults.certificate?.valid) {
                    localResults.riskScore = Math.max(0, localResults.riskScore - 1);
                    
                    // Check for trusted issuers
                    const issuer = sslResults.certificate.issuer?.toLowerCase() || '';
                    const trustedIssuers = ['digicert', 'let\'s encrypt', 'globalsign', 'sectigo', 'comodo'];
                    
                    if (trustedIssuers.some(trusted => issuer.includes(trusted))) {
                        localResults.riskScore = Math.max(0, localResults.riskScore - 2);
                    }
                }

                // Integrate backend risk assessment
                if (sslResults.risk_level) {
                    const backendRisk = sslResults.risk_level.toLowerCase();
                    if (backendRisk.includes('high')) {
                        localResults.riskScore += 5;
                    } else if (backendRisk.includes('medium')) {
                        localResults.riskScore += 3;
                    }
                }

                // Add Google Safe Browsing results
                if (sslResults.google_safe_browsing?.safe === false) {
                    localResults.riskScore += 8;
                    localResults.checks.push({
                        type: 'Malicious Website Detected',
                        message: 'Google Safe Browsing detected this site as potentially harmful',
                        risk: 'high',
                        severity: 8
                    });
                }
                
                // Recalculate risk level based on updated score
                if (localResults.riskScore >= 8) localResults.riskLevel = 'high';
                else if (localResults.riskScore >= 4) localResults.riskLevel = 'medium';
                else localResults.riskLevel = 'low';

                localResults.ssl = {
                    valid: sslResults.certificate.valid,
                    issuer: sslResults.certificate.issuer,
                    common_name: sslResults.certificate.common_name,
                    valid_from: sslResults.certificate.valid_from,
                    valid_until: sslResults.certificate.valid_until,
                    feedback: sslResults.feedback,
                    risk_level: sslResults.risk_level
                };

                localResults.googleSafeBrowsing = sslResults.google_safe_browsing;

            } else {
                localResults.ssl = { error: sslResults.error };
            }

        } catch (err) {
            localResults.ssl = { error: 'Failed to analyze SSL certificate' };
        }

        setResults(localResults);
        setIsAnalyzing(false);
    };

    const performAnalysis = (inputUrl) => {
        const analysis = {
            url: inputUrl,
            timestamp: new Date().toLocaleString(),
            riskLevel: 'low',
            riskScore: 0,
            checks: [],
            recommendations: []
        };

        let riskScore = 0;
        const detectedIssues = [];

        if (!inputUrl.startsWith('https://')) {
            detectedIssues.push({
                type: 'No HTTPS',
                message: 'Website does not use secure HTTPS protocol',
                risk: 'medium',
                severity: 3
            });
            riskScore += 3;
        }

        let domain = '';
        try {
            const urlObj = new URL(inputUrl.startsWith('http') ? inputUrl : 'https://' + inputUrl);
            domain = urlObj.hostname;
        } catch (e) {
            detectedIssues.push({
                type: 'Invalid URL',
                message: 'URL format is invalid or malformed',
                risk: 'high',
                severity: 5
            });
            riskScore += 5;
        }

        suspiciousPatterns.forEach(({ pattern, name, risk }) => {
            if (pattern.test(inputUrl) || pattern.test(domain)) {
                const severity = risk === 'high' ? 4 : risk === 'medium' ? 2 : 1;
                detectedIssues.push({
                    type: name,
                    message: `Detected: ${name}`,
                    risk,
                    severity
                });
                riskScore += severity;
            }
        });

        if (domain.split('.').length > 4) {
            detectedIssues.push({
                type: 'Multiple Subdomains',
                message: 'Excessive subdomain levels detected',
                risk: 'medium',
                severity: 2
            });
            riskScore += 2;
        }

        if (inputUrl.length > 100) {
            detectedIssues.push({
                type: 'Long URL',
                message: 'URL is unusually long',
                risk: 'medium',
                severity: 2
            });
            riskScore += 2;
        }

        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            detectedIssues.push({
                type: 'URL Shortener',
                message: 'Uses URL shortening service',
                risk: 'medium',
                severity: 2
            });
            riskScore += 2;
        }

        if (riskScore >= 8) analysis.riskLevel = 'high';
        else if (riskScore >= 4) analysis.riskLevel = 'medium';
        else analysis.riskLevel = 'low';

        analysis.riskScore = riskScore;
        analysis.checks = detectedIssues;

        if (detectedIssues.length === 0) {
            analysis.recommendations.push('URL appears to be safe based on initial analysis');
        } else {
            analysis.recommendations.push('Exercise caution when visiting this website');
            analysis.recommendations.push("Verify the website's legitimacy through official channels");
            analysis.recommendations.push('Do not enter sensitive information unless verified');
        }

        return analysis;
    };

    const getRiskColor = (risk) => {
        switch (risk) {
            case 'high': return 'text-red-300 bg-red-500/20 border-red-500/30';
            case 'medium': return 'text-orange-300 bg-orange-500/20 border-orange-500/30';
            case 'low': return 'text-green-300 bg-green-500/20 border-green-500/30';
            default: return 'text-gray-300 bg-gray-500/20 border-gray-500/30';
        }
    };

    const getRiskIcon = (risk) => {
        switch (risk) {
            case 'high': return <XCircle className="w-5 h-5" />;
            case 'medium': return <AlertTriangle className="w-5 h-5" />;
            case 'low': return <CheckCircle className="w-5 h-5" />;
            default: return <AlertCircle className="w-5 h-5" />;
        }
    };

    const getSafeBrowsingColor = (safe) => {
        if (safe === true) return 'text-green-300 bg-green-500/20 border-green-500/30';
        if (safe === false) return 'text-red-300 bg-red-500/20 border-red-500/30';
        return 'text-gray-300 bg-gray-500/20 border-gray-500/30';
    };

    const getSafeBrowsingIcon = (safe) => {
        if (safe === true) return <CheckCircle className="w-5 h-5" />;
        if (safe === false) return <XCircle className="w-5 h-5" />;
        return <AlertCircle className="w-5 h-5" />;
    };

    return (
        <div className="relative min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 overflow-hidden">

            {/* Background Pattern */}
            <div className="absolute inset-0 opacity-10">
                <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-orange-500/20 via-transparent to-green-500/20"></div>
                <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-gradient-to-r from-orange-500/10 to-green-500/10 rounded-full blur-3xl animate-pulse"></div>
                <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-gradient-to-r from-green-500/10 to-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
            </div>

            <div className="relative z-10 flex items-center justify-center min-h-screen py-16 px-4">
                <div className="max-w-6xl mx-auto w-full">
                    <div className="backdrop-blur-xl bg-white/10 border border-white/20 rounded-3xl shadow-2xl overflow-hidden">
                        <div className="p-8 lg:p-12">
                            {/* Header */}
                            <div className="text-center mb-12">
                                <div className="flex items-center justify-center mb-6">
                                    <div className="w-16 h-16 bg-gradient-to-br from-orange-500 to-green-500 rounded-2xl flex items-center justify-center shadow-lg mr-4">
                                        <Shield className="w-8 h-8 text-white" />
                                    </div>
                                    <h1 className="text-4xl lg:text-5xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text">
                                        Website Security Checker
                                    </h1>
                                </div>
                                <p className="text-xl text-gray-300 leading-relaxed max-w-2xl mx-auto">
                                    Comprehensive URL analysis with SSL certificate validation, Google Safe Browsing, and AI-powered threat detection
                                </p>
                            </div>

                            {/* URL Input */}
                            <div className="mb-12">
                                <label className="block text-sm font-medium text-gray-300 mb-4">
                                    Enter Website URL for Security Analysis
                                </label>
                                <div className="flex gap-4">
                                    <div className="flex-1 relative">
                                        <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 w-6 h-6 text-gray-400" />
                                        <input
                                            type="text"
                                            value={url}
                                            onChange={(e) => setUrl(e.target.value)}
                                            placeholder="https://example.com or paste any suspicious URL"
                                            className="w-full pl-12 pr-4 py-4 bg-white/10 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all duration-300 text-lg"
                                            onKeyPress={(e) => e.key === 'Enter' && analyzeUrl()}
                                        />
                                    </div>
                                    <button
                                        onClick={analyzeUrl}
                                        disabled={!url.trim() || isAnalyzing}
                                        className="group relative bg-gradient-to-r from-orange-500 to-green-500 hover:from-orange-600 hover:to-green-600 text-white font-bold py-4 px-8 rounded-xl transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-orange-500/25 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 overflow-hidden"
                                    >
                                        {/* Button shine effect */}
                                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-700"></div>
                                        <span className="relative flex items-center">
                                            {isAnalyzing ? (
                                                <>
                                                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                                                    Analyzing...
                                                </>
                                            ) : (
                                                <>
                                                    <Shield className="w-5 h-5 mr-2" />
                                                    Analyze URL
                                                </>
                                            )}
                                        </span>
                                    </button>
                                </div>
                            </div>

                            {/* Results */}
                            {results && (
                                <div className="space-y-8">
                                    {/* Risk Level Summary */}
                                    <div className={`p-6 rounded-2xl border-2 backdrop-blur-sm ${getRiskColor(results.riskLevel)}`}>
                                        <div className="flex items-center mb-6">
                                            <div className="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center mr-4">
                                                {getRiskIcon(results.riskLevel)}
                                            </div>
                                            <div>
                                                <h3 className="text-2xl font-bold">Risk Level: {results.riskLevel.toUpperCase()}</h3>
                                                <p className="text-sm opacity-75">Comprehensive security analysis completed</p>
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                            <div className="bg-white/10 p-4 rounded-xl">
                                                <div className="text-sm opacity-75">URL</div>
                                                <div className="font-medium truncate">{results.url}</div>
                                            </div>
                                            <div className="bg-white/10 p-4 rounded-xl">
                                                <div className="text-sm opacity-75">Risk Score</div>
                                                <div className="font-medium">{results.riskScore}/25</div>
                                            </div>
                                            <div className="bg-white/10 p-4 rounded-xl">
                                                <div className="text-sm opacity-75">Analyzed</div>
                                                <div className="font-medium">{results.timestamp}</div>
                                            </div>
                                            <div className="bg-white/10 p-4 rounded-xl">
                                                <div className="text-sm opacity-75">Issues Found</div>
                                                <div className="font-medium">{results.checks.length}</div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Google Safe Browsing Results */}
                                    {results.googleSafeBrowsing && (
                                        <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                                            <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
                                                <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center mr-3">
                                                    <Search className="w-4 h-4 text-white" />
                                                </div>
                                                Google Safe Browsing Check
                                            </h3>
                                            
                                            <div className={`p-4 rounded-xl border-2 ${getSafeBrowsingColor(results.googleSafeBrowsing.safe)}`}>
                                                <div className="flex items-center mb-3">
                                                    {getSafeBrowsingIcon(results.googleSafeBrowsing.safe)}
                                                    <span className="font-bold ml-3">
                                                        {results.googleSafeBrowsing.safe === true && "Safe - No threats detected"}
                                                        {results.googleSafeBrowsing.safe === false && "Dangerous - Threats detected"}
                                                        {results.googleSafeBrowsing.safe === null && "Check unavailable"}
                                                    </span>
                                                </div>
                                                
                                                {results.googleSafeBrowsing.safe === false && results.googleSafeBrowsing.details && (
                                                    <div className="mt-4 space-y-2">
                                                        <div className="text-sm font-medium">Detected threats:</div>
                                                        {results.googleSafeBrowsing.details.map((threat, index) => (
                                                            <div key={index} className="bg-white/10 p-3 rounded-lg">
                                                                <div className="text-sm">
                                                                    <strong>Type:</strong> {threat.threatType}
                                                                </div>
                                                                <div className="text-sm">
                                                                    <strong>Platform:</strong> {threat.platformType}
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}

                                                {results.googleSafeBrowsing.error && (
                                                    <div className="mt-2 text-sm opacity-75">
                                                        {results.googleSafeBrowsing.error}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* SSL Certificate Analysis */}
                                    {results.ssl && (
                                        <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                                            <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
                                                <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center mr-3">
                                                    <FileText className="w-4 h-4 text-white" />
                                                </div>
                                                SSL Certificate Analysis
                                            </h3>
                                            
                                            {results.ssl.error ? (
                                                <div className="bg-red-500/20 border border-red-500/30 p-4 rounded-xl">
                                                    <div className="flex items-center text-red-300">
                                                        <XCircle className="w-5 h-5 mr-3" />
                                                        <span className="font-medium">SSL Analysis Failed:</span>
                                                    </div>
                                                    <p className="text-red-200 mt-2">{results.ssl.error}</p>
                                                </div>
                                            ) : (
                                                <div className="space-y-4">
                                                    {/* Certificate Status */}
                                                    <div className={`p-4 rounded-xl border-2 ${results.ssl.valid ? 'bg-green-500/20 border-green-500/30' : 'bg-red-500/20 border-red-500/30'}`}>
                                                        <div className="flex items-center justify-between mb-3">
                                                            <div className="flex items-center">
                                                                {results.ssl.valid ? (
                                                                    <CheckCircle className="w-5 h-5 text-green-400 mr-3" />
                                                                ) : (
                                                                    <XCircle className="w-5 h-5 text-red-400 mr-3" />
                                                                )}
                                                                <span className={`font-bold ${results.ssl.valid ? 'text-green-300' : 'text-red-300'}`}>
                                                                    Certificate {results.ssl.valid ? 'Valid' : 'Invalid'}
                                                                </span>
                                                            </div>
                                                            {results.ssl.risk_level && (
                                                                <div className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getRiskColor(results.ssl.risk_level.toLowerCase().replace(' risk', ''))}`}>
                                                                    {results.ssl.risk_level}
                                                                </div>
                                                            )}
                                                        </div>
                                                        
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                            <div className="bg-white/10 p-3 rounded-lg">
                                                                <div className="text-sm opacity-75">Issuer</div>
                                                                <div className="font-medium">{results.ssl.issuer}</div>
                                                            </div>
                                                            <div className="bg-white/10 p-3 rounded-lg">
                                                                <div className="text-sm opacity-75">Common Name</div>
                                                                <div className="font-medium">{results.ssl.common_name}</div>
                                                            </div>
                                                            <div className="bg-white/10 p-3 rounded-lg">
                                                                <div className="text-sm opacity-75">Valid From</div>
                                                                <div className="font-medium">{results.ssl.valid_from}</div>
                                                            </div>
                                                            <div className="bg-white/10 p-3 rounded-lg">
                                                                <div className="text-sm opacity-75">Valid Until</div>
                                                                <div className="font-medium">{results.ssl.valid_until}</div>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* AI Feedback */}
                                                    {results.ssl.feedback && (
                                                        <div className="bg-gradient-to-r from-purple-500/20 to-blue-500/20 border border-purple-500/30 p-4 rounded-xl">
                                                            <div className="flex items-center mb-3">
                                                                <div className="w-8 h-8 bg-gradient-to-r from-purple-500 to-blue-500 rounded-lg flex items-center justify-center mr-3">
                                                                    <Bot className="w-4 h-4 text-white" />
                                                                </div>
                                                                <h4 className="text-lg font-bold text-white">AI Security Analysis</h4>
                                                            </div>
                                                            <div className="bg-white/10 p-4 rounded-lg">
                                                                <p className="text-gray-300 leading-relaxed">{results.ssl.feedback}</p>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Detected Issues */}
                                    {results.checks.length > 0 ? (
                                        <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                                            <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
                                                <div className="w-8 h-8 bg-gradient-to-br from-orange-500 to-red-500 rounded-lg flex items-center justify-center mr-3">
                                                    <Eye className="w-4 h-4 text-white" />
                                                </div>
                                                Detected Security Issues
                                            </h3>
                                            <div className="space-y-4">
                                                {results.checks.map((check, index) => (
                                                    <div key={index} className={`group p-4 rounded-xl border-2 backdrop-blur-sm hover:bg-white/5 transition-all duration-300 ${getRiskColor(check.risk)}`}>
                                                        <div className="flex items-start">
                                                            <div className="w-10 h-10 bg-white/10 rounded-lg flex items-center justify-center mr-4 flex-shrink-0">
                                                                {getRiskIcon(check.risk)}
                                                            </div>
                                                            <div className="flex-grow">
                                                                <div className="font-semibold text-lg">{check.type}</div>
                                                                <div className="text-sm opacity-75 mt-1">{check.message}</div>
                                                            </div>
                                                            <div className="flex-shrink-0">
                                                                <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getRiskColor(check.risk)}`}>
                                                                    {check.risk}
                                                                </span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="backdrop-blur-sm bg-green-500/20 border border-green-500/30 p-6 rounded-2xl">
                                            <div className="flex items-center text-green-300">
                                                <div className="w-12 h-12 bg-green-500/30 rounded-xl flex items-center justify-center mr-4">
                                                    <CheckCircle className="w-6 h-6" />
                                                </div>
                                                <div>
                                                    <h3 className="text-xl font-bold">No Security Issues Detected</h3>
                                                    <p className="text-green-200 mt-1">
                                                        The URL appears to be safe based on our comprehensive security analysis.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Security Recommendations */}
                                    <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                                        <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
                                            <div className="w-8 h-8 bg-gradient-to-br from-green-500 to-blue-500 rounded-lg flex items-center justify-center mr-3">
                                                <Lock className="w-4 h-4 text-white" />
                                            </div>
                                            Security Recommendations
                                        </h3>
                                        <div className="space-y-3">
                                            {results.recommendations.map((rec, index) => (
                                                <div key={index} className="flex items-start bg-white/5 p-4 rounded-xl">
                                                    <div className="w-2 h-2 bg-gradient-to-r from-orange-500 to-green-500 rounded-full mt-2 mr-4 flex-shrink-0"></div>
                                                    <span className="text-gray-300">{rec}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Disclaimer */}
                                    <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                                        <div className="flex items-start">
                                            <AlertTriangle className="w-6 h-6 text-yellow-400 mr-4 flex-shrink-0" />
                            <div>
                                <h4 className="font-semibold text-yellow-300 mb-2">Security Analysis Disclaimer</h4>
                                <p className="text-gray-400 text-sm leading-relaxed">
                                    This security analysis provides automated threat detection based on URL patterns, SSL certificates, and external security databases. 
                                    While comprehensive, it should not be considered a substitute for professional security assessment. 
                                    Always exercise caution when visiting unfamiliar websites and avoid entering sensitive information unless you're certain of the site's legitimacy.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    </div>
</div>
</div>
</div>
        );
    }