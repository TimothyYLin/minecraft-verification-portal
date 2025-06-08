import React, { createContext, useState, useContext, useEffect} from 'react';
import { jwtDecode } from 'jwt-decode';

const AuthContext = createContext(null);

export function AuthProvider({ children }){
    const [token, setToken] = useState(localStorage.getItem('authToken'));
    const [user, setUser] = useState(null);

    useEffect(() => {
        if(token){
            try{
                const decodedUser = jwtDecode(token);

                const currentTime = Date.now() / 1000;
                if(decodedUser.exp < currentTime){
                    console.log("Token expired, logging out.");
                    setToken(null);
                    setUser(null);
                    localStorage.removeItem('authToken');
                }else{
                    setUser(decodedUser);
                    localStorage.setItem('authToken', token);
                }
            }catch(error){
                console.error("Invalid token:", error);
                setUser(null);
                setToken(null);
                localStorage.removeItem('authToken');
            }
        }else{
            localStorage.removeItem('authToken');
            setUser(null);
        }
    }, [token]);

    const login = (newToken) => {
        setToken(newToken);
    };

    const logout = () => {
        setToken(null);
    };

    const isAuthenticated = !!token;

    const value = { isAuthenticated, token, user, login, logout };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}

export function useAuth(){
    const context = useContext(AuthContext);
    if(!context){
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}