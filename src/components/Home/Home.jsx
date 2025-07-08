import React from 'react';
import image from '../../assets/image.png'
export default function Home() {
    return (
        <div className="min-h-screen w-full bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
            <aside className="relative overflow-hidden rounded-lg sm:mx-16 mx-2 sm:py-16 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
                {/* Animated Background Elements */}
                <div className="absolute inset-0 opacity-10">
                    <div className="absolute top-0 left-0 w-72 h-72 bg-orange-500 rounded-full blur-3xl animate-pulse"></div>
                    <div className="absolute bottom-0 right-0 w-96 h-96 bg-green-500 rounded-full blur-3xl animate-pulse delay-1000"></div>
                    <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-blue-500 rounded-full blur-3xl animate-pulse delay-500"></div>
                </div>

                {/* Decorative Top Wave */}
                <div className="absolute top-0 left-0 w-full h-16 bg-gradient-to-r from-orange-500 to-green-500 opacity-20 transform -skew-y-1"></div>

                <div className="relative z-10 max-w-screen-xl px-4 pb-20 pt-10 sm:py-24 mx-auto sm:px-6 lg:px-8">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
                        {/* Video Section - Left Side */}
                        <div className="relative">
                            <div className="relative w-full h-96 lg:h-[500px] rounded-2xl overflow-hidden shadow-2xl">
                                {/* Video Element */}
                                <video 
                                    className="w-full h-full object-cover"
                                    muted 
                                    autoPlay 
                                    loop
                                    playsInline
                                    // poster={image}
                                >
                                    <source src="https://videos.pexels.com/video-files/30767358/13160994_2560_1440_30fps.mp4" type="video/mp4" />
                                    Your browser does not support the video tag.
                                </video>
                                
                                {/* Video Overlay */}
                                <div className="absolute inset-0 bg-gradient-to-t from-gray-900/60 via-transparent to-transparent"></div>
                                
                                {/* Play Button Overlay */}
                                {/* <div className="absolute inset-0 flex items-center justify-center">
                                    <div className="w-20 h-20 bg-white/20 backdrop-blur-sm rounded-full flex items-center justify-center group-hover:bg-white/30 transition-all duration-300 cursor-pointer">
                                        <svg className="w-8 h-8 text-white ml-1" fill="currentColor" viewBox="0 0 24 24">
                                            <path d="M8 5v14l11-7z"/>
                                        </svg>
                                    </div>
                                </div> */}
                                
                                {/* Video Caption */}
                                
                            </div>
                            
                            {/* Decorative Elements around Video */}
                            <div className="absolute -top-4 -left-4 w-8 h-8 bg-orange-500 rounded-full animate-pulse"></div>
                            <div className="absolute -bottom-4 -right-4 w-6 h-6 bg-green-500 rounded-full animate-pulse delay-500"></div>
                            <div className="absolute top-1/2 -right-2 w-4 h-4 bg-blue-500 rounded-full animate-bounce"></div>
                        </div>

                        {/* Content Section - Right Side */}
                        <div className="space-y-8 text-center lg:text-left">
                            <div className="space-y-4">
                                <h2 className="text-4xl font-bold sm:text-5xl text-white leading-tight">
                                    <span className="block text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text">
                                        Download Now
                                    </span>
                                    <span className="block text-4xl text-transparent bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text mt-2">
                                        EcoTrust
                                    </span>
                                </h2>
                                
                                {/* Subtitle */}
                                <p className="text-lg text-gray-300 max-w-md mx-auto lg:mx-0">
                                    Join the sustainable revolution with our cutting-edge eco-friendly platform
                                </p>
                            </div>
                             
                            {/* Enhanced Download Button */}
                            <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
                                <button
                                    className="group relative inline-flex items-center px-8 py-4 font-bold text-white bg-gradient-to-r from-orange-500 to-green-500 rounded-2xl hover:from-orange-600 hover:to-green-600 transform hover:scale-105 transition-all duration-300 shadow-2xl hover:shadow-orange-500/25 overflow-hidden"
                                    onClick={() => window.open('#', '_blank')}
                                >
                                    {/* Button shine effect */}
                                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-700"></div>
                                    
                                    <div className="relative flex items-center">
                                        <div className="w-6 h-6 bg-white/20 rounded-full flex items-center justify-center mr-3 group-hover:rotate-12 transition-transform duration-300">
                                            <svg
                                                fill="white"
                                                width="16"
                                                height="16"
                                                xmlns="http://www.w3.org/2000/svg"
                                                fillRule="evenodd"
                                                clipRule="evenodd"
                                            >
                                                <path d="M1.571 23.664l10.531-10.501 3.712 3.701-12.519 6.941c-.476.264-1.059.26-1.532-.011l-.192-.13zm9.469-11.56l-10.04 10.011v-20.022l10.04 10.011zm6.274-4.137l4.905 2.719c.482.268.781.77.781 1.314s-.299 1.046-.781 1.314l-5.039 2.793-4.015-4.003 4.149-4.137zm-15.854-7.534c.09-.087.191-.163.303-.227.473-.271 1.056-.275 1.532-.011l12.653 7.015-3.846 3.835-10.642-10.612z" />
                                            </svg>
                                        </div>
                                        <span className="text-lg">Download Now</span>
                                    </div>
                                </button>
                                {/* Secondary Button */}
                                <button
                                    className="group inline-flex items-center px-8 py-4 font-semibold text-gray-300 bg-white/10 backdrop-blur-sm rounded-2xl hover:bg-white/20 hover:text-white transform hover:scale-105 transition-all duration-300 border border-white/20 hover:border-orange-500/50"
                                    onClick={() => window.open('#', '_blank')}
                                >
                                    <span className="text-lg mr-2">📱</span>
                                    Learn More
                                </button>
                            </div>

                            {/* Feature Pills */}
                            <div className="flex flex-wrap justify-center lg:justify-start gap-3">
                                <span className="px-4 py-2 bg-orange-500/20 text-orange-300 rounded-full text-sm font-medium border border-orange-500/30">
                                    🤖 AI-Powered
                                </span>
                                <span className="px-4 py-2 bg-green-500/20 text-green-300 rounded-full text-sm font-medium border border-green-500/30">
                                    🔍 Insightful
                                </span>
                                <span className="px-4 py-2 bg-blue-500/20 text-blue-300 rounded-full text-sm font-medium border border-blue-500/30">
                                    🔐 Secure
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Floating Elements */}
                <div className="absolute top-20 left-10 w-4 h-4 bg-orange-400 rounded-full animate-bounce delay-100"></div>
                <div className="absolute bottom-20 right-20 w-6 h-6 bg-green-400 rounded-full animate-bounce delay-300"></div>
                <div className="absolute top-1/2 left-20 w-3 h-3 bg-blue-400 rounded-full animate-bounce delay-500"></div>
            </aside>
             
            {/* Stats Section */}
            <div className="mt-16 mb-8">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 sm:mx-16 mx-2">
                    <div className="text-center group">
                        <div className="w-16 h-16 bg-gradient-to-br from-orange-500 to-orange-600 rounded-2xl flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform duration-300">
                            <span className="text-2xl">🛡️</span>
                        </div>
                        <h3 className="text-2xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-orange-600 bg-clip-text">
                            1M+
                        </h3>
                        <p className="text-gray-600 mt-2">Threats Detected</p>
                    </div>
                    
                    <div className="text-center group">
                        <div className="w-16 h-16 bg-gradient-to-br from-green-500 to-green-600 rounded-2xl flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform duration-300">
                            <span className="text-2xl">🔒</span>
                        </div>
                        <h3 className="text-2xl font-bold text-transparent bg-gradient-to-r from-green-400 to-green-600 bg-clip-text">
                            500K+
                        </h3>
                        <p className="text-gray-600 mt-2">Websites Secured</p>
                    </div>
                    
                    <div className="text-center group">
                        <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform duration-300">
                            <span className="text-2xl">👥</span>
                        </div>
                        <h3 className="text-2xl font-bold text-transparent bg-gradient-to-r from-blue-400 to-blue-600 bg-clip-text">
                            100K+
                        </h3>
                        <p className="text-gray-600 mt-2">Active Users</p>
                    </div>
                </div>
            </div>

            {/* Features Section */}
            <div className="py-16 bg-gradient-to-br from-gray-800 to-gray-900 sm:mx-16 mx-2 rounded-2xl mb-8">
                <div className="max-w-6xl mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-4xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text mb-4">
                            Why Choose EcoTrust?
                        </h2>
                        <p className="text-xl text-gray-300 max-w-2xl mx-auto">
                            Discover the powerful features that make EcoTrust the ultimate platform for sustainable living
                        </p>
                    </div>
                    
                   <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        {/* Threat Detection */}
                        <div className="group bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-red-500/50 transition-all duration-300 hover:bg-white/10">
                            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <span className="text-xl">🛡️</span>
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">Threat Detection</h3>
                            <p className="text-gray-400">Real-time detection of malware, phishing sites, and other online threats.</p>
                        </div>

                        {/* Website Scanner */}
                        <div className="group bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-cyan-500/50 transition-all duration-300 hover:bg-white/10">
                            <div className="w-12 h-12 bg-gradient-to-br from-cyan-500 to-cyan-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <span className="text-xl">🔍</span>
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">Website Scanner</h3>
                            <p className="text-gray-400">Paste any URL and check for security issues, blacklisting, and unsafe links.</p>
                        </div>

                        {/* Data Privacy Alerts */}
                        <div className="group bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-purple-500/50 transition-all duration-300 hover:bg-white/10">
                            <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <span className="text-xl">🔐</span>
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">Privacy Alerts</h3>
                            <p className="text-gray-400">Get notified when your data is at risk or found in a breach.</p>
                        </div>

                        {/* Secure Browsing Tips */}
                        <div className="group bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-blue-500/50 transition-all duration-300 hover:bg-white/10">
                            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <span className="text-xl">💡</span>
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">Secure Browsing</h3>
                            <p className="text-gray-400">Learn best practices to browse the web safely and avoid harmful websites.</p>
                        </div>

                        {/* Incident Reporting */}
                        <div className="group bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-yellow-500/50 transition-all duration-300 hover:bg-white/10">
                            <div className="w-12 h-12 bg-gradient-to-br from-yellow-500 to-yellow-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <span className="text-xl">🚨</span>
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">Incident Reporting</h3>
                            <p className="text-gray-400">Report suspicious activity or websites for investigation and user safety.</p>
                        </div>

                        {/* Cyber Awareness Training */}
                        <div className="group bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-green-500/50 transition-all duration-300 hover:bg-white/10">
                            <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-green-600 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <span className="text-xl">🎓</span>
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">Cyber Awareness</h3>
                            <p className="text-gray-400">Educate users with tips and training to prevent social engineering attacks.</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Testimonials Section */}
            <div className="py-16 sm:mx-16 mx-2">
                <div className="max-w-6xl mx-auto px-4">
                    <div className="text-center mb-12">
                        <h2 className="text-4xl font-bold text-transparent bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text mb-4">
                            What Our Users Say
                        </h2>
                        <p className="text-xl text-gray-400 max-w-2xl mx-auto">
                            Join thousands of satisfied users staying safe online with EcoTrust
                        </p>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        <div className="bg-gradient-to-br from-orange-500/10 to-orange-600/10 backdrop-blur-sm rounded-2xl p-6 border border-orange-500/20">
                            <div className="flex items-center mb-4">
                                <div className="w-12 h-12 bg-gradient-to-br from-orange-400 to-orange-500 rounded-full flex items-center justify-center text-white font-bold">
                                    S
                                </div>
                                <div className="ml-3">
                                    <h4 className="text-white font-semibold">Sarah Johnson</h4>
                                    <p className="text-gray-400 text-sm">Cybersecurity Analyst</p>
                                </div>
                            </div>
                            <p className="text-gray-300 italic">"EcoTrust has transformed how I monitor my online security. The insights are incredible!"</p>
                            <div className="flex mt-3">
                                <span className="text-orange-400">⭐⭐⭐⭐⭐</span>
                            </div>
                        </div>
                        
                        <div className="bg-gradient-to-br from-green-500/10 to-green-600/10 backdrop-blur-sm rounded-2xl p-6 border border-green-500/20">
                            <div className="flex items-center mb-4">
                                <div className="w-12 h-12 bg-gradient-to-br from-green-400 to-green-500 rounded-full flex items-center justify-center text-white font-bold">
                                    M
                                </div>
                                <div className="ml-3">
                                    <h4 className="text-white font-semibold">Mike Chen</h4>
                                    <p className="text-gray-400 text-sm">IT Security Specialist</p>
                                </div>
                            </div>
                            <p className="text-gray-300 italic">"The threat detection feature is amazing. I feel much safer browsing the web!"</p>
                            <div className="flex mt-3">
                                <span className="text-green-400">⭐⭐⭐⭐⭐</span>
                            </div>
                        </div>
                        
                        <div className="bg-gradient-to-br from-blue-500/10 to-blue-600/10 backdrop-blur-sm rounded-2xl p-6 border border-blue-500/20">
                            <div className="flex items-center mb-4">
                                <div className="w-12 h-12 bg-gradient-to-br from-blue-400 to-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                                    A
                                </div>
                                <div className="ml-3">
                                    <h4 className="text-white font-semibold">Alex Rivera</h4>
                                    <p className="text-gray-400 text-sm">Penetration Tester</p>
                                </div>
                            </div>
                            <p className="text-gray-300 italic">"One of the easiest and most reliable platforms for web security analysis."</p>
                            <div className="flex mt-3">
                                <span className="text-blue-400">⭐⭐⭐⭐⭐</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Newsletter Section */}
            <div className="py-16 bg-gradient-to-br from-gray-900 to-gray-800 sm:mx-16 mx-2 rounded-2xl mb-8">
                <div className="max-w-4xl mx-auto px-4 text-center">
                    <h2 className="text-4xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text mb-4">
                        Stay Updated
                    </h2>
                    <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
                        Get the latest cybersecurity tips, updates, and exclusive content delivered to your inbox
                    </p>
                    
                    <div className="flex flex-col sm:flex-row gap-4 justify-center max-w-md mx-auto">
                        <input
                            type="email"
                            placeholder="Enter your email"
                            className="flex-1 px-6 py-4 bg-white/10 backdrop-blur-sm rounded-2xl text-white placeholder-gray-400 border border-white/20 focus:border-orange-500/50 focus:outline-none focus:bg-white/20 transition-all duration-300"
                        />
                        <button className="px-8 py-4 bg-gradient-to-r from-orange-500 to-green-500 text-white font-bold rounded-2xl hover:from-orange-600 hover:to-green-600 transform hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-orange-500/25">
                            Subscribe
                        </button>
                    </div>
                    
                    <p className="text-gray-500 text-sm mt-4">
                        No spam, unsubscribe anytime. We respect your privacy.
                    </p>
                </div>
            </div>

            {/* Call to Action Section */}
            <div className="py-20 sm:mx-16 mx-2">
                <div className="max-w-4xl mx-auto text-center">
                    <h2 className="text-5xl font-bold text-transparent bg-gradient-to-r from-orange-400 via-green-400 to-blue-400 bg-clip-text mb-6">
                        Ready to Make a Difference?
                    </h2>
                    <p className="text-2xl text-gray-300 mb-8 max-w-3xl mx-auto">
                        Join the EcoTrust community today and start your journey towards a more sustainable future
                    </p>
                    
                    <div className="flex flex-col sm:flex-row gap-6 justify-center">
                        <button
                            className="group relative inline-flex items-center px-12 py-6 text-xl font-bold text-white bg-gradient-to-r from-orange-500 to-green-500 rounded-2xl hover:from-orange-600 hover:to-green-600 transform hover:scale-105 transition-all duration-300 shadow-2xl hover:shadow-orange-500/25 overflow-hidden"
                            onClick={() => window.open('#', '_blank')}
                        >
                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-700"></div>
                            <div className="relative flex items-center">
                                <span className="text-2xl mr-3">🚀</span>
                                Get Started Free
                            </div>
                        </button>
                        
                        <button
                            className="group inline-flex items-center px-12 py-6 text-xl font-semibold text-gray-300 bg-white/10 backdrop-blur-sm rounded-2xl hover:bg-white/20 hover:text-white transform hover:scale-105 transition-all duration-300 border border-white/20 hover:border-green-500/50"
                            onClick={() => window.open('#', '_blank')}
                        >
                            <span className="text-2xl mr-3">📖</span>
                            View Demo
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}