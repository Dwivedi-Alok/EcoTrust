import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import image from '../../assets/image.png'
export default function Header() {
    const [isMenuOpen, setIsMenuOpen] = useState(false);

    const toggleMenu = () => {
        setIsMenuOpen(!isMenuOpen);
    };

    return (
        <header className="shadow-2xl sticky z-50 top-0 bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 backdrop-blur-md border-b border-gray-700/50">
            <div className="w-full h-1 bg-gradient-to-r from-orange-500 via-green-500 to-blue-500"></div>

            <nav className="px-4 lg:px-6 py-3">
                <div className="flex flex-wrap justify-between items-center mx-auto max-w-screen-xl">
                    <Link to="" className="flex items-center group">
                        <div className="relative">
                            <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-green-500 rounded-2xl flex items-center justify-center shadow-2xl group-hover:shadow-orange-500/25 transition-all duration-300 group-hover:scale-110">
                                <span className="text-lg font-bold text-white">ECO</span>
                            </div>
                            <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-400 rounded-full animate-ping"></div>
                        </div>
                        <div className="ml-3">
                            <h1 className="text-xl font-bold text-transparent bg-gradient-to-r from-orange-400 to-green-400 bg-clip-text">
                                EcoTrust
                            </h1>
                            <p className="text-xs text-gray-400">Sustainable Future</p>
                        </div>
                    </Link>

                    <div className="flex items-center lg:order-2">
                        <Link
                            to="/login"
                            className="group text-gray-300 hover:text-white bg-white/10 hover:bg-white/20 backdrop-blur-sm border border-white/20 hover:border-orange-500/50 font-medium rounded-xl text-sm px-5 py-2.5 mr-3 transition-all duration-300 transform hover:scale-105"
                        >
                            <span className="flex items-center">
                                <span className="mr-2">👤</span>
                                Log in
                            </span>
                        </Link>
                        <Link
                            to="/get-started"
                            className="group relative text-white bg-gradient-to-r from-orange-500 to-green-500 hover:from-orange-600 hover:to-green-600 font-bold rounded-xl text-sm px-6 py-2.5 mr-3 transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-orange-500/25 overflow-hidden"
                        >
                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12 -translate-x-full group-hover:translate-x-full transition-transform duration-700"></div>
                            <span className="relative flex items-center">
                                <span className="mr-2">🚀</span>
                                Get Started
                            </span>
                        </Link>

                        <button
                            onClick={toggleMenu}
                            className="lg:hidden p-2 text-gray-300 hover:text-white bg-white/10 hover:bg-white/20 rounded-xl transition-all duration-300"
                        >
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={isMenuOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"} />
                            </svg>
                        </button>
                    </div>

                    <div className="hidden lg:flex lg:w-auto lg:order-1">
                        <ul className="flex flex-row space-x-8 font-medium">
                            <li>
                                <Link
                                    to=""
                                    className="group relative block py-2 px-4 text-gray-300 hover:text-white transition-all duration-300"
                                >
                                    <span className="relative z-10">Home</span>
                                    <div className="absolute inset-0 bg-gradient-to-r from-orange-500/20 to-green-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                    <div className="absolute bottom-0 left-0 w-0 h-0.5 bg-gradient-to-r from-orange-500 to-green-500 group-hover:w-full transition-all duration-300"></div>
                                </Link>
                            </li>
                          <li>
  <Link
    to="PasteUrl"
    className="group relative block py-2 px-4 text-gray-300 hover:text-white transition-all duration-300"
  >
    <span className="relative z-10">Analyse Website</span>
    <div className="absolute inset-0 bg-gradient-to-r from-orange-500/20 to-green-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
    <div className="absolute bottom-0 left-0 w-0 h-0.5 bg-gradient-to-r from-orange-500 to-green-500 group-hover:w-full transition-all duration-300"></div>
  </Link>
</li>

                            <li>
                                <Link
                                    to="/about"
                                    className="group relative block py-2 px-4 text-gray-300 hover:text-white transition-all duration-300"
                                >
                                    <span className="relative z-10">About</span>
                                    <div className="absolute inset-0 bg-gradient-to-r from-green-500/20 to-blue-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                    <div className="absolute bottom-0 left-0 w-0 h-0.5 bg-gradient-to-r from-green-500 to-blue-500 group-hover:w-full transition-all duration-300"></div>
                                </Link>
                            </li>
                            <li>
                                <Link
                                    to="/contact"
                                    className="group relative block py-2 px-4 text-gray-300 hover:text-white transition-all duration-300"
                                >
                                    <span className="relative z-10">Contact</span>
                                    <div className="absolute inset-0 bg-gradient-to-r from-blue-500/20 to-purple-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                    <div className="absolute bottom-0 left-0 w-0 h-0.5 bg-gradient-to-r from-blue-500 to-purple-500 group-hover:w-full transition-all duration-300"></div>
                                </Link>
                            </li>
                        </ul>
                    </div>
                </div>

                <div className={`lg:hidden transition-all duration-300 ease-in-out ${isMenuOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}>
                    <div className="mt-4 pt-4 border-t border-gray-700/50">
                        <ul className="space-y-3">
                            <li>
                                <Link
                                    to=""
                                    className="group flex items-center py-3 px-4 text-gray-300 hover:text-white bg-white/5 hover:bg-gradient-to-r hover:from-orange-500/20 hover:to-green-500/20 rounded-xl transition-all duration-300"
                                >
                                    <span className="w-2 h-2 bg-orange-500 rounded-full mr-3 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></span>
                                    <span className="transform group-hover:translate-x-2 transition-transform duration-300">Home</span>
                                </Link>
                            </li>
                            <li>
                           <Link
                           to="/PasteUrl"
                           className="group relative block py-2 px-4 text-gray-300 hover:text-white transition-all duration-300"
                           >
                          <span className="relative z-10">Analyse Website</span>
                          <div className="absolute inset-0 bg-gradient-to-r from-orange-500/20 to-green-500/20 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                          <div className="absolute bottom-0 left-0 w-0 h-0.5 bg-gradient-to-r from-orange-500 to-green-500 group-hover:w-full transition-all duration-300"></div>
                          </Link>
                          </li>


                            <li>
                                <Link
                                    to="/about"
                                    className="group flex items-center py-3 px-4 text-gray-300 hover:text-white bg-white/5 hover:bg-gradient-to-r hover:from-green-500/20 hover:to-blue-500/20 rounded-xl transition-all duration-300"
                                >
                                    <span className="w-2 h-2 bg-green-500 rounded-full mr-3 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></span>
                                    <span className="transform group-hover:translate-x-2 transition-transform duration-300">About</span>
                                </Link>
                            </li>
                            <li>
                                <Link
                                    to="/contact"
                                    className="group flex items-center py-3 px-4 text-gray-300 hover:text-white bg-white/5 hover:bg-gradient-to-r hover:from-blue-500/20 hover:to-purple-500/20 rounded-xl transition-all duration-300"
                                >
                                    <span className="w-2 h-2 bg-blue-500 rounded-full mr-3 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></span>
                                    <span className="transform group-hover:translate-x-2 transition-transform duration-300">Contact</span>
                                </Link>
                            </li>
                        </ul>

                        <div className="mt-6 space-y-3">
                            <Link
                                to="/login"
                                className="block w-full text-center text-gray-300 hover:text-white bg-white/10 hover:bg-white/20 backdrop-blur-sm border border-white/20 hover:border-orange-500/50 font-medium rounded-xl text-sm px-5 py-3 transition-all duration-300"
                            >
                                👤 Log in
                            </Link>
                            <Link
                                to="/get-started"
                                className="block w-full text-center text-white bg-gradient-to-r from-orange-500 to-green-500 hover:from-orange-600 hover:to-green-600 font-bold rounded-xl text-sm px-6 py-3 transition-all duration-300 shadow-lg"
                            >
                                🚀 Get Started
                            </Link>
                        </div>
                    </div>
                </div>
            </nav>
        </header>
    );
}
