import React from 'react';
import { Link } from 'react-router-dom';

export default function Footer() {
  return (
    <footer className="relative bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-0 left-0 w-72 h-72 bg-orange-500 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-green-500 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-blue-500 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      {/* Decorative Top Wave */}
      <div className="absolute top-0 left-0 w-full h-16 bg-gradient-to-r from-orange-500 to-green-500 opacity-20 transform -skew-y-1"></div>

      <div className="relative max-w-screen-xl mx-auto px-4 py-16 sm:px-6 lg:px-8">
        <div className="md:flex md:justify-between md:items-start">
          {/* Logo Section */}
          <div className="mb-12 md:mb-0 transform hover:scale-105 transition-transform duration-300">
            <a href="/" className="flex items-center group">
              <div className="relative">
                <div className="w-16 h-16 bg-gradient-to-br from-orange-500 to-green-500 rounded-2xl flex items-center justify-center shadow-2xl group-hover:shadow-orange-500/25 transition-all duration-300">
                  <span className="text-2xl font-bold text-white">ECO</span>
                </div>
                <div className="absolute -top-2 -right-2 w-6 h-6 bg-green-400 rounded-full animate-ping"></div>
              </div>
              <div className="ml-4">
                <h3 className="text-2xl font-bold bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text text-transparent">
                  EcoTrust
                </h3>
                <p className="text-sm text-gray-400 mt-1">Building a sustainable future</p>
              </div>
            </a>
          </div>

          {/* Links Grid */}
          <div className="grid grid-cols-1 gap-12 sm:grid-cols-3 w-full md:w-2/3">
            {/* Resources */}
            <div className="group">
              <h2 className="mb-6 text-lg font-bold uppercase tracking-wide text-transparent bg-gradient-to-r from-orange-400 to-orange-600 bg-clip-text relative">
                Resources
                <div className="absolute -bottom-2 left-0 w-0 h-0.5 bg-gradient-to-r from-orange-500 to-green-500 group-hover:w-full transition-all duration-500"></div>
              </h2>
             <ul className="space-y-4 text-sm">
  <li>
    <Link 
      to="" 
      className="flex items-center text-gray-300 hover:text-orange-400 transition-all duration-300 group/item"
    >
      <span className="w-2 h-2 bg-orange-500 rounded-full mr-3 opacity-0 group-hover/item:opacity-100 transition-opacity duration-300"></span>
      <span className="transform group-hover/item:translate-x-2 transition-transform duration-300">Home</span>
    </Link>
  </li>
  <li>
    <Link 
      to="about" 
      className="flex items-center text-gray-300 hover:text-orange-400 transition-all duration-300 group/item"
    >
      <span className="w-2 h-2 bg-orange-500 rounded-full mr-3 opacity-0 group-hover/item:opacity-100 transition-opacity duration-300"></span>
      <span className="transform group-hover/item:translate-x-2 transition-transform duration-300">About</span>
    </Link>
  </li>
</ul>

            </div>

            {/* Follow Us */}
            <div className="group">
              <h2 className="mb-6 text-lg font-bold uppercase tracking-wide text-transparent bg-gradient-to-r from-green-400 to-green-600 bg-clip-text relative">
                Follow us
                <div className="absolute -bottom-2 left-0 w-0 h-0.5 bg-gradient-to-r from-green-500 to-blue-500 group-hover:w-full transition-all duration-500"></div>
              </h2>
              <ul className="space-y-4 text-sm">
                <li>
                  <Link
                    to="https://github.com/Dwivedi-Alok"
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center text-gray-300 hover:text-green-400 transition-all duration-300 group/item"
                  >
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-3 opacity-0 group-hover/item:opacity-100 transition-opacity duration-300"></span>
                    <span className="transform group-hover/item:translate-x-2 transition-transform duration-300">GitHub</span>
                  </Link>
                </li>
                <li>
                  <a 
                    href="#" 
                    className="flex items-center text-gray-300 hover:text-green-400 transition-all duration-300 group/item"
                  >
                    <span className="w-2 h-2 bg-green-500 rounded-full mr-3 opacity-0 group-hover/item:opacity-100 transition-opacity duration-300"></span>
                    <span className="transform group-hover/item:translate-x-2 transition-transform duration-300">Discord</span>
                  </a>
                </li>
              </ul>
            </div>

            {/* Legal */}
            <div className="group">
              <h2 className="mb-6 text-lg font-bold uppercase tracking-wide text-transparent bg-gradient-to-r from-blue-400 to-purple-600 bg-clip-text relative">
                Legal
                <div className="absolute -bottom-2 left-0 w-0 h-0.5 bg-gradient-to-r from-blue-500 to-purple-500 group-hover:w-full transition-all duration-500"></div>
              </h2>
              <ul className="space-y-4 text-sm">
                <li>
                  <a 
                    href="#" 
                    className="flex items-center text-gray-300 hover:text-blue-400 transition-all duration-300 group/item"
                  >
                    <span className="w-2 h-2 bg-blue-500 rounded-full mr-3 opacity-0 group-hover/item:opacity-100 transition-opacity duration-300"></span>
                    <span className="transform group-hover/item:translate-x-2 transition-transform duration-300">Privacy Policy</span>
                  </a>
                </li>
                <li>
                  <a 
                    href="#" 
                    className="flex items-center text-gray-300 hover:text-blue-400 transition-all duration-300 group/item"
                  >
                    <span className="w-2 h-2 bg-blue-500 rounded-full mr-3 opacity-0 group-hover/item:opacity-100 transition-opacity duration-300"></span>
                    <span className="transform group-hover/item:translate-x-2 transition-transform duration-300">Terms & Conditions</span>
                  </a>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Divider with Gradient */}
        <div className="my-12 relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full h-px bg-gradient-to-r from-transparent via-gray-600 to-transparent"></div>
          </div>
          <div className="relative flex justify-center">
            <div className="w-16 h-16 bg-gradient-to-br from-orange-500 to-green-500 rounded-full flex items-center justify-center">
              <div className="w-8 h-8 bg-white rounded-full flex items-center justify-center">
                <div className="w-4 h-4 bg-gradient-to-br from-orange-500 to-green-500 rounded-full"></div>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="flex flex-col sm:flex-row sm:justify-between items-center">
          <span className="text-sm text-gray-400 flex items-center">
            © 2025 
            <span className="mx-2 text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text font-bold">
              EcoTrust
            </span>
            . All Rights Reserved.
            <span className="ml-2 text-xs px-2 py-1 bg-gradient-to-r from-orange-500 to-green-500 rounded-full text-white animate-pulse">
              ✨ New
            </span>
          </span>
          
          {/* Social Media Icons */}
          <div className="flex space-x-6 mt-6 sm:mt-0">
            <a 
              href="#" 
              className="group w-12 h-12 bg-gradient-to-br from-gray-700 to-gray-800 rounded-full flex items-center justify-center hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-110 hover:shadow-lg hover:shadow-blue-500/25"
            >
              <span className="text-lg group-hover:text-white transition-colors">📘</span>
            </a>
            <a 
              href="#" 
              className="group w-12 h-12 bg-gradient-to-br from-gray-700 to-gray-800 rounded-full flex items-center justify-center hover:from-sky-500 hover:to-sky-600 transition-all duration-300 transform hover:scale-110 hover:shadow-lg hover:shadow-sky-500/25"
            >
              <span className="text-lg group-hover:text-white transition-colors">🐦</span>
            </a>
            <a 
              href="#" 
              className="group w-12 h-12 bg-gradient-to-br from-gray-700 to-gray-800 rounded-full flex items-center justify-center hover:from-gray-600 hover:to-gray-700 transition-all duration-300 transform hover:scale-110 hover:shadow-lg hover:shadow-gray-500/25"
            >
              <span className="text-lg group-hover:text-white transition-colors">🐱</span>
            </a>
          </div>
        </div>

        {/* Newsletter Signup */}
        <div className="mt-12 p-8 bg-gradient-to-r from-orange-500/10 to-green-500/10 rounded-2xl border border-orange-500/20 backdrop-blur-sm">
          <div className="text-center">
            <h3 className="text-2xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text mb-3">
              Stay Connected
            </h3>
            <p className="text-gray-400 mb-6">Join our community for the latest updates on sustainable technology</p>
            <div className="flex flex-col sm:flex-row gap-4 max-w-md mx-auto">
              <input
                type="email"
                placeholder="Enter your email"
                className="flex-1 px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all duration-300"
              />
              <button className="px-6 py-3 bg-gradient-to-r from-orange-500 to-green-500 text-white rounded-lg font-semibold hover:from-orange-600 hover:to-green-600 transform hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-orange-500/25">
                Subscribe
              </button>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}