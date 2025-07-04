import React from 'react';
import logo from '../../assets/Logo.png';
import { Link } from 'react-router-dom';
export default function About() {
  return (
    <div className="relative min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0">
        <div className="absolute top-20 left-10 w-72 h-72 bg-orange-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute top-40 right-20 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute bottom-20 left-1/3 w-80 h-80 bg-green-500/10 rounded-full blur-3xl animate-pulse delay-2000"></div>
      </div>
      
      {/* Floating Particles */}
      <div className="absolute inset-0 overflow-hidden">
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            className="absolute w-1 h-1 bg-white/20 rounded-full animate-ping"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 3}s`,
              animationDuration: `${2 + Math.random() * 2}s`
            }}
          />
        ))}
      </div>

      <div className="relative z-10 container mx-auto px-6 py-24 md:px-12 xl:px-6">
        <div className="space-y-16 md:space-y-0 md:flex md:gap-16 lg:items-center lg:gap-20">
          {/* Logo Section */}
          <div className="md:w-5/12 lg:w-5/12 relative group">
            <div className="relative">
              {/* Glowing backdrop */}
              <div className="absolute inset-0 bg-gradient-to-r from-orange-500/20 via-green-500/20 to-blue-500/20 rounded-3xl blur-2xl group-hover:blur-3xl transition-all duration-700"></div>
              
              {/* Main logo container */}
              <div className="relative bg-white/5 backdrop-blur-xl rounded-3xl p-8 border border-white/10 shadow-2xl group-hover:shadow-orange-500/25 transition-all duration-700 group-hover:scale-105">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500 via-green-500 to-blue-500 rounded-t-3xl"></div>
                <img
                  src={logo}
                  alt="SecureGuard Logo"
                  className="w-full drop-shadow-2xl"
                />
                
                {/* Floating security icons */}
                <div className="absolute -top-4 -right-4 w-8 h-8 bg-green-500 rounded-full flex items-center justify-center shadow-lg animate-bounce">
                  <span className="text-white text-sm">🛡️</span>
                </div>
                <div className="absolute -bottom-4 -left-4 w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center shadow-lg animate-bounce delay-500">
                  <span className="text-white text-sm">🔒</span>
                </div>
              </div>
            </div>
          </div>

          {/* Content Section */}
          <div className="md:w-7/12 lg:w-6/12 space-y-8">
            {/* Main Heading */}
            <div className="relative">
              <h2 className="text-4xl md:text-6xl font-black text-transparent bg-gradient-to-r from-orange-400 via-green-400 to-blue-400 bg-clip-text leading-tight">
                Your First Line of Defense
              </h2>
              <h3 className="text-3xl md:text-5xl font-bold text-white mt-2 drop-shadow-lg">
                Against Online Fraud
              </h3>
              <div className="absolute -top-2 -left-2 w-4 h-4 bg-orange-500 rounded-full animate-ping"></div>
              <div className="absolute top-4 -right-4 w-3 h-3 bg-green-500 rounded-full animate-ping delay-1000"></div>
            </div>

            {/* Feature Cards */}
            <div className="space-y-6">
              <div className="group relative bg-white/5 backdrop-blur-xl rounded-2xl p-6 border border-white/10 hover:border-orange-500/30 transition-all duration-500 hover:shadow-xl hover:shadow-orange-500/10">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-orange-500 to-red-500 rounded-t-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <div className="flex items-start space-x-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-red-500 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                    <span className="text-white text-xl">🔍</span>
                  </div>
                  <div className="flex-1">
                    <h4 className="text-white font-bold text-lg mb-2">Advanced Threat Detection</h4>
                    <p className="text-gray-300 leading-relaxed">
                      Our AI-powered system analyzes suspicious patterns, unsafe content, and cross-references with global scam databases to identify threats before they reach you.
                    </p>
                  </div>
                </div>
              </div>

              <div className="group relative bg-white/5 backdrop-blur-xl rounded-2xl p-6 border border-white/10 hover:border-green-500/30 transition-all duration-500 hover:shadow-xl hover:shadow-green-500/10">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-green-500 to-emerald-500 rounded-t-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <div className="flex items-start space-x-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                    <span className="text-white text-xl">⚡</span>
                  </div>
                  <div className="flex-1">
                    <h4 className="text-white font-bold text-lg mb-2">Instant Analysis</h4>
                    <p className="text-gray-300 leading-relaxed">
                      Just paste a link and get immediate results. Whether you're shopping online, receiving unknown links, or browsing new sites, we ensure you know if it's safe.
                    </p>
                  </div>
                </div>
              </div>

              <div className="group relative bg-white/5 backdrop-blur-xl rounded-2xl p-6 border border-white/10 hover:border-blue-500/30 transition-all duration-500 hover:shadow-xl hover:shadow-blue-500/10">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-purple-500 rounded-t-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <div className="flex items-start space-x-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                    <span className="text-white text-xl">🛡️</span>
                  </div>
                  <div className="flex-1">
                    <h4 className="text-white font-bold text-lg mb-2">Proactive Protection</h4>
                    <p className="text-gray-300 leading-relaxed">
                      <span className="text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text font-semibold">Stay informed. Stay protected. Stay one step ahead of scammers.</span>
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Call to Action Quote */}
            <div className="relative">
              <div className="bg-gradient-to-r from-orange-500/10 via-green-500/10 to-blue-500/10 backdrop-blur-xl rounded-2xl p-8 border border-white/10 shadow-2xl">
                <div className="absolute top-4 left-4 text-4xl text-orange-500/50">"</div>
                <div className="absolute bottom-4 right-4 text-4xl text-blue-500/50 rotate-180">"</div>
                <p className="text-center text-xl font-bold text-white leading-relaxed">
                  Think it's suspicious? Let us check.
                  <br />
                  <span className="text-transparent bg-gradient-to-r from-orange-400 to-blue-400 bg-clip-text">
                    We help you stay scam-free.
                  </span>
                </p>
              </div>
            </div>

            {/* Action Button */}
            <Link
      to=""
  className="group relative inline-flex items-center justify-center bg-gradient-to-r from-orange-500 via-green-500 to-blue-500 hover:from-orange-600 hover:via-green-600 hover:to-blue-600 text-white font-bold py-4 px-8 rounded-2xl shadow-2xl hover:shadow-orange-500/25 transition-all duration-500 transform hover:scale-105 overflow-hidden"
>
  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-1000"></div>
  <span className="relative flex items-center text-lg">
    <span className="mr-3">🚀</span>
    Start Protecting Yourself Now
    <span className="ml-3">→</span>
  </span>
</Link>

          </div>
        </div>
      </div>
    </div>
  );
}