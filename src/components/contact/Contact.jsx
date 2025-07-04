import React, { useState } from 'react';

export default function Contact() {
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        tel: '',
        message: ''
    });

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        // Handle form submission here
        console.log('Form submitted:', formData);
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
                        <div className="grid grid-cols-1 lg:grid-cols-2">
                            {/* Left Side - Contact Info */}
                            <div className="p-8 lg:p-12 bg-gradient-to-br from-gray-800/50 to-gray-900/50 backdrop-blur-sm">
                                <div className="space-y-8">
                                    <div>
                                        <h1 className="text-4xl lg:text-5xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text mb-4">
                                            Get in Touch
                                        </h1>
                                        <p className="text-xl text-gray-300 leading-relaxed">
                                            Have questions about online security? Need help with suspicious links? 
                                            We're here to help keep you safe.
                                        </p>
                                    </div>

                                    <div className="space-y-6">
                                        {/* Security Operations Center */}
                                        <div className="group flex items-start space-x-4 p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-all duration-300">
                                            <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-orange-500 to-green-500 rounded-xl flex items-center justify-center shadow-lg group-hover:shadow-orange-500/25 transition-all duration-300">
                                                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <h3 className="text-white font-semibold mb-1">Security Operations Center</h3>
                                                <p className="text-gray-400">24/7 Fraud Detection & Prevention</p>
                                                <p className="text-gray-500 text-sm">Global Network Security Division</p>
                                            </div>
                                        </div>

                                        {/* Emergency Hotline */}
                                        <div className="group flex items-start space-x-4 p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-all duration-300">
                                            <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-green-500 to-blue-500 rounded-xl flex items-center justify-center shadow-lg group-hover:shadow-green-500/25 transition-all duration-300">
                                                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <h3 className="text-white font-semibold mb-1">Emergency Hotline</h3>
                                                <p className="text-gray-400">+1 (800) SECURE-1</p>
                                                <p className="text-gray-500 text-sm">Report suspicious activity immediately</p>
                                            </div>
                                        </div>

                                        {/* Secure Communications */}
                                        <div className="group flex items-start space-x-4 p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-all duration-300">
                                            <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center shadow-lg group-hover:shadow-blue-500/25 transition-all duration-300">
                                                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <h3 className="text-white font-semibold mb-1">Secure Communications</h3>
                                                <p className="text-gray-400">security@trustguard.com</p>
                                                <p className="text-gray-500 text-sm">Encrypted end-to-end messaging</p>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Security Badge */}
                                    <div className="mt-8 p-4 bg-gradient-to-r from-orange-500/20 to-green-500/20 rounded-xl border border-orange-500/30">
                                        <div className="flex items-center space-x-3">
                                            <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                                                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                                </svg>
                                            </div>
                                            <div>
                                                <p className="text-white font-semibold">Certified Security Partner</p>
                                                <p className="text-gray-400 text-sm">Your data is protected with enterprise-grade encryption</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Right Side - Contact Form */}
                            <div className="p-8 lg:p-12 bg-white/5 backdrop-blur-sm">
                                <div className="space-y-6">
                                    <div>
                                        <h2 className="text-2xl font-bold text-white mb-6">Send Secure Message</h2>
                                    </div>

                                    <div className="space-y-4">
                                        <div>
                                            <label htmlFor="name" className="block text-sm font-medium text-gray-300 mb-2">
                                                Full Name
                                            </label>
                                            <input
                                                type="text"
                                                name="name"
                                                id="name"
                                                value={formData.name}
                                                onChange={handleChange}
                                                placeholder="Enter your full name"
                                                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all duration-300"
                                            />
                                        </div>

                                        <div>
                                            <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                                                Email Address
                                            </label>
                                            <input
                                                type="email"
                                                name="email"
                                                id="email"
                                                value={formData.email}
                                                onChange={handleChange}
                                                placeholder="your.email@example.com"
                                                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all duration-300"
                                            />
                                        </div>

                                        <div>
                                            <label htmlFor="tel" className="block text-sm font-medium text-gray-300 mb-2">
                                                Phone Number
                                            </label>
                                            <input
                                                type="tel"
                                                name="tel"
                                                id="tel"
                                                value={formData.tel}
                                                onChange={handleChange}
                                                placeholder="+1 (555) 123-4567"
                                                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all duration-300"
                                            />
                                        </div>

                                        <div>
                                            <label htmlFor="message" className="block text-sm font-medium text-gray-300 mb-2">
                                                Message
                                            </label>
                                            <textarea
                                                name="message"
                                                id="message"
                                                rows={4}
                                                value={formData.message}
                                                onChange={handleChange}
                                                placeholder="Describe your security concern or question..."
                                                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all duration-300 resize-none"
                                            />
                                        </div>
                                    </div>

                                    <button
                                        onClick={handleSubmit}
                                        className="group relative w-full bg-gradient-to-r from-orange-500 to-green-500 hover:from-orange-600 hover:to-green-600 text-white font-bold py-4 px-8 rounded-xl transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-orange-500/25 overflow-hidden"
                                    >
                                        {/* Button shine effect */}
                                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-700"></div>
                                        <span className="relative flex items-center justify-center">
                                            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                            </svg>
                                            Send Secure Message
                                        </span>
                                    </button>

                                    <p className="text-xs text-gray-400 text-center">
                                        🔒 All communications are encrypted and secure
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}