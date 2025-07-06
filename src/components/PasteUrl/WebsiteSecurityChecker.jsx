import React, { useState } from 'react';
import { AlertTriangle, Shield, CheckCircle, XCircle, Globe, Lock, Eye, AlertCircle, FileText, Bot, Search, ExternalLink } from 'lucide-react';

export default function WebsiteSecurityChecker() {
    const [url, setUrl] = useState('');
    const [results, setResults] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    const suspiciousPatterns = [
  { pattern: /^(http[s]?:\/\/)?(\d{1,3}\.){3}\d{1,3}$/, name: 'Direct IP Address Access', risk: 'high' },
  { pattern: /\.(tk|ml|ga|cf|gq|xyz|pw|top|click|fit|review|space|tech)$/, name: 'Suspicious TLD', risk: 'medium' },
  { pattern: /\.(onion|bit)$/, name: 'Darknet / Onion domain', risk: 'high' },
  { pattern: /[0-9]{10,}/, name: 'Unusually Long Number Sequence', risk: 'medium' },
  { pattern: /[a-zA-Z0-9-]{30,}/, name: 'Unusually Long Domain Name', risk: 'medium' },
  { pattern: /^([^.]+\.){4,}/, name: 'Excessive Subdomains', risk: 'medium' },
  { pattern: /[^a-zA-Z0-9.-]/, name: 'Special Characters in Domain', risk: 'high' },
  { pattern: /(?:^|[-.])(paypal|amazon|apple|microsoft|facebook|twitter|linkedin|github)(?:[-.]|$)/i, name: 'Brand Impersonation Pattern', risk: 'high' },
  { pattern: /secure|login|verify|update|confirm|account/i, name: 'Phishing Keywords', risk: 'medium' },
  { pattern: /crypto|bit|wallet|blockchain/i, name: 'Crypto Keyword in Domain', risk: 'medium' }
];


    const checkSSLCertificate = async (hostname) => {
        try {
            // Add timeout and better error handling
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

            const response = await fetch('https://webscarping-x2tm.onrender.com/api/check-ssl', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ hostname }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('SSL Check API error:', error);
            
            // Provide more specific error messages
            if (error.name === 'AbortError') {
                return { error: 'SSL analysis request timed out. Please try again.' };
            } else if (error.message.includes('Failed to fetch')) {
                return { error: 'Unable to connect to SSL analysis service. The service may be temporarily unavailable.' };
            } else if (error.message.includes('HTTP')) {
                return { error: `SSL analysis service error: ${error.message}` };
            } else {
                return { error: 'SSL analysis temporarily unavailable. Local analysis completed.' };
            }
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
                   const trustedIssuers = ['digicert', 'let\'s encrypt', 'globalsign', 'sectigo', 'comodo', 'google trust'];
;
                    
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
               if (localResults.riskScore >= 6) localResults.riskLevel = 'high';
               else if (localResults.riskScore >= 32) localResults.riskLevel = 'medium';
               else localResults.riskLevel = 'low';

                localResults.ssl = {
                    valid: sslResults.certificate?.valid || false,
                    issuer: sslResults.certificate?.issuer || 'Unknown',
                    common_name: sslResults.certificate?.common_name || 'Unknown',
                    valid_from: sslResults.certificate?.valid_from || 'Unknown',
                    valid_until: sslResults.certificate?.valid_until || 'Unknown',
                    feedback: sslResults.feedback || 'No additional feedback available',
                    risk_level: sslResults.risk_level || 'Unknown'
                };

                localResults.googleSafeBrowsing = sslResults.google_safe_browsing || { safe: null, error: 'Check unavailable' };

            } else {
                localResults.ssl = { error: sslResults.error };
                // Add a note that local analysis was completed
                localResults.checks.push({
                    type: 'SSL Analysis Unavailable',
                    message: 'External SSL verification service is temporarily unavailable. Local analysis completed.',
                    risk: 'low',
                    severity: 0
                });
            }

        } catch (err) {
    console.error('Analysis error:', err);
    localResults.ssl = {
        error: 'Failed to analyze SSL certificate - service may be unavailable'
    };

    // Push a real penalty for the SSL failure
    localResults.checks.push({
        type: 'SSL Analysis Error',
        message: 'Unable to verify SSL certificate. Domain may be insecure or malicious.',
        risk: 'medium',
        severity: 3
    });

    localResults.riskScore += 3;


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

  // Ensure protocol + domain parsed properly
  let domain = '';
  let parsedUrl;

  try {
    parsedUrl = new URL(inputUrl.startsWith('http') ? inputUrl : 'https://' + inputUrl);
    domain = parsedUrl.hostname;
  } catch (e) {
    detectedIssues.push({
      type: 'Invalid URL',
      message: 'URL format is invalid or malformed',
      risk: 'high',
      severity: 5
    });
    riskScore += 5;
    analysis.riskScore = riskScore;
    analysis.riskLevel = 'high';
    analysis.checks = detectedIssues;
    return analysis;
  }

  // 🔐 HTTPS check (now uses resolved protocol)
  if (parsedUrl.protocol !== 'https:') {
    detectedIssues.push({
      type: 'No HTTPS',
      message: 'Website does not use secure HTTPS protocol',
      risk: 'medium',
      severity: 3
    });
    riskScore += 3;
  }

  // 🧠 Suspicious patterns
  const suspiciousPatterns = [
    { pattern: /^[0-9.]+$/, name: 'IP Address Instead of Domain', risk: 'high' },
    { pattern: /\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/, name: 'Free or Abused TLD', risk: 'medium' },
    { pattern: /[0-9]{3,}/, name: 'Numeric Pattern in Domain', risk: 'medium' },
    { pattern: /(login|secure|update|account|verify|signin)/i, name: 'Suspicious Keywords', risk: 'medium' },
    { pattern: /-(paypal|apple|amazon|google|bank|wallet)/i, name: 'Brand Impersonation Pattern', risk: 'high' },
    { pattern: /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.link)\b/, name: 'URL Shortener', risk: 'medium' }
  ];

  suspiciousPatterns.forEach(({ pattern, name, risk }) => {
    if (pattern.test(domain)) {
      const severity = risk === 'high' ? 4 : risk === 'medium' ? 2 : 1;
      detectedIssues.push({ type: 'Pattern Match', message: `Detected: ${name}`, risk, severity });
      riskScore += severity;
    }
  });

  // 🧠 Subdomain depth
  if (domain.split('.').length > 4) {
    detectedIssues.push({
      type: 'Excessive Subdomains',
      message: 'Suspicious subdomain structure detected',
      risk: 'medium',
      severity: 2
    });
    riskScore += 2;
  }

  // 🧠 Excessive length
  if (inputUrl.length > 100) {
    detectedIssues.push({
      type: 'Long URL',
      message: 'URL is unusually long',
      risk: 'low',
      severity: 1
    });
    riskScore += 1;
  }

  // 🧠 Whitelist check (no penalty)
  const whitelistedDomains = ['google.com', 'www.google.com', 'microsoft.com', 'apple.com'];
  if (whitelistedDomains.includes(domain)) {
    riskScore = 0;
    detectedIssues.length = 0;
    analysis.recommendations.push('URL is verified and commonly trusted.');
  }

  // Final risk level
  if (riskScore >= 7) analysis.riskLevel = 'high';
  else if (riskScore >= 3) analysis.riskLevel = 'medium';
  else analysis.riskLevel = 'low';

  analysis.riskScore = riskScore;
  analysis.checks = detectedIssues;

  if (detectedIssues.length === 0) {
    analysis.recommendations.push('URL appears safe based on initial checks.');
  } else {
    analysis.recommendations.push('Exercise caution when visiting this website.');
    analysis.recommendations.push('Verify the website’s legitimacy through official sources.');
    analysis.recommendations.push('Do not enter sensitive info unless verified.');
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
                                            <div className="font-medium break-all">{results.url}</div>
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
                                    {/* Additional URL Info */}
                                    <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                                     <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
        <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-lg flex items-center justify-center mr-3">
            <Globe className="w-4 h-4 text-white" />
        </div>
        URL Analysis Details
    </h3>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="bg-white/10 p-4 rounded-xl">
            <div className="text-sm opacity-75">Protocol</div>
            <div className="font-medium">{results.url.startsWith('https://') ? 'HTTPS ✓' : 'HTTP ⚠️'}</div>
        </div>
        <div className="bg-white/10 p-4 rounded-xl">
            <div className="text-sm opacity-75">Domain</div>
            <div className="font-medium break-all">{(() => {
                try {
                    return new URL(results.url.startsWith('http') ? results.url : 'https://' + results.url).hostname;
                } catch (e) {
                    return 'Invalid URL';
                }
            })()}</div>
        </div>
        <div className="bg-white/10 p-4 rounded-xl">
            <div className="text-sm opacity-75">URL Length</div>
            <div className="font-medium">{results.url.length} characters</div>
        </div>
    </div>
    </div>
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
                                                <div className="bg-orange-500/20 border border-orange-500/30 p-4 rounded-xl">
                                                    <div className="flex items-center text-orange-300">
                                                        <AlertTriangle className="w-5 h-5 mr-3" />
                                                        <span className="font-medium">SSL Analysis Notice:</span>
                                                    </div>
                                                    <p className="text-orange-200 mt-2">{results.ssl.error}</p>
                                                    <p className="text-orange-200 mt-2 text-sm">Local security analysis has been completed successfully.</p>
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
                                                            {results.ssl.risk_level && results.ssl.risk_level !== 'Unknown' && (
                                                                <div className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getRiskColor(results.ssl.risk_level.toLowerCase().replace(' risk', ''))}`}>
                                                                    {results.ssl.risk_level}
                                                                </div>
                                                            )}
                                                        </div>
                                                        
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                           <div className="bg-white/10 p-3 rounded-lg">
    <div className="text-sm opacity-75">Issuer</div>
    <div className="font-medium break-all">{results.ssl.issuer}</div>
</div>
<div className="bg-white/10 p-3 rounded-lg">
    <div className="text-sm opacity-75">Common Name</div>
    <div className="font-medium break-all">{results.ssl.common_name}</div>
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
                                                    {results.ssl.feedback && results.ssl.feedback !== 'No additional feedback available' && (
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
                                    <h3 className="text-2xl font-bold">No Security Issues Detected</h3>
                                    <p className="text-sm opacity-75 mt-2">The URL appears to be safe based on our analysis</p>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Recommendations */}
                    {results.recommendations.length > 0 && (
                        <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                            <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
                                <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center mr-3">
                                    <AlertCircle className="w-4 h-4 text-white" />
                                </div>
                                Security Recommendations
                            </h3>
                            <div className="space-y-3">
                                {results.recommendations.map((rec, index) => (
                                    <div key={index} className="flex items-start bg-white/10 p-4 rounded-xl">
                                        <div className="w-6 h-6 bg-blue-500/30 rounded-full flex items-center justify-center mr-3 flex-shrink-0 mt-0.5">
                                            <span className="text-blue-300 text-sm font-bold">{index + 1}</span>
                                        </div>
                                        <span className="text-gray-300">{rec}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Additional Security Tips */}
                    <div className="backdrop-blur-sm bg-white/5 border border-white/20 p-6 rounded-2xl">
                        <h3 className="text-2xl font-bold mb-6 flex items-center text-white">
                            <div className="w-8 h-8 bg-gradient-to-br from-green-500 to-teal-500 rounded-lg flex items-center justify-center mr-3">
                                <Lock className="w-4 h-4 text-white" />
                            </div>
                            General Security Tips
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="bg-white/10 p-4 rounded-xl">
                                <div className="flex items-center mb-3">
                                    <Shield className="w-5 h-5 text-green-400 mr-2" />
                                    <span className="font-semibold text-green-300">Always verify URLs</span>
                                </div>
                                <p className="text-sm text-gray-300">Double-check URLs before clicking, especially in emails or messages</p>
                            </div>
                            <div className="bg-white/10 p-4 rounded-xl">
                                <div className="flex items-center mb-3">
                                    <Lock className="w-5 h-5 text-blue-400 mr-2" />
                                    <span className="font-semibold text-blue-300">Look for HTTPS</span>
                                </div>
                                <p className="text-sm text-gray-300">Ensure websites use HTTPS encryption, especially for sensitive data</p>
                            </div>
                            <div className="bg-white/10 p-4 rounded-xl">
                                <div className="flex items-center mb-3">
                                    <Eye className="w-5 h-5 text-purple-400 mr-2" />
                                    <span className="font-semibold text-purple-300">Check certificates</span>
                                </div>
                                <p className="text-sm text-gray-300">Verify SSL certificates for authenticity and validity</p>
                            </div>
                            <div className="bg-white/10 p-4 rounded-xl">
                                <div className="flex items-center mb-3">
                                    <AlertTriangle className="w-5 h-5 text-orange-400 mr-2" />
                                    <span className="font-semibold text-orange-300">Trust your instincts</span>
                                </div>
                                <p className="text-sm text-gray-300">If something seems suspicious, don't proceed and verify independently</p>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    </div>

    {/* Footer */}
    <div className="relative z-10 text-center py-8 px-4">
        <div className="backdrop-blur-sm bg-white/5 border border-white/20 rounded-2xl p-6 max-w-4xl mx-auto">
            <div className="flex items-center justify-center mb-4">
                <Shield className="w-6 h-6 text-orange-400 mr-2" />
                <span className="text-lg font-semibold text-white">Website Security Checker</span>
            </div>
            <p className="text-gray-300 mb-4">
                Advanced URL analysis combining local pattern recognition, SSL certificate validation, and Google Safe Browsing checks
            </p>
            <div className="flex items-center justify-center text-sm text-gray-400">
                <span>Powered by AI-driven security analysis</span>
                <span className="mx-2">•</span>
                <span>Real-time threat detection</span>
                <span className="mx-2">•</span>
                <span>Comprehensive reporting</span>
            </div>
        </div>
    </div>
</div>
</div>
</div>
);
}