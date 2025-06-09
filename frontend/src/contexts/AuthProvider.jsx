import React, { useState, useEffect, useCallback, useRef } from 'react';
import { jwtDecode } from 'jwt-decode';
import api, { setAuthToken, logoutUser } from '@/services/apiService';
import { AuthContext } from '@/contexts/AuthContext';

export function AuthProvider({ children }){
    const [user, setUser] = useState(null);
    const [isLoading, setIsLoading] = useState(true);

    const initialLoadAttempt = useRef(false);

    const login = useCallback((accessToken) => {
        if(!accessToken){
            console.error("Login function called without a token.");
            return;
        }
        setAuthToken(accessToken);
        try{
            const decodedUser = jwtDecode(accessToken);
            setUser(decodedUser);
        }catch(error){
            console.error("Could not decode token", error);
            setUser(null);
            setAuthToken(null);
        }
    }, []);

    const logout = useCallback(async () => {
        try{
            await logoutUser();
        }catch(error){
            console.error("server logout failed, logging out client-side anyway.", error);
        }finally{
            setUser(null);
            setAuthToken(null);
        }
    }, []);

    useEffect(() => {
        if(initialLoadAttempt.current){
            return;
        }
        initialLoadAttempt.current = true;

        const loadInitialUser = async () => {
            try {
                const { data } = await api.post('/refresh-token');
                if (data.token) {
                    login(data.token);
                }
            } catch (error) {
                console.log("No active session found on page load.");
            } finally {
                setIsLoading(false);
            }
        };

        loadInitialUser();

    }, [login]);

    useEffect(() => {
        const handleLoginEvent = (event) => login(event.detail);
        const handleLogoutEvent = () => logout();

        window.addEventListener('loginSuccess', handleLoginEvent);
        window.addEventListener('logout', handleLogoutEvent);

        return () => {
            window.removeEventListener('loginSuccess', handleLoginEvent);
            window.removeEventListener('logout', handleLogoutEvent);
        };
    }, [login, logout]);

    const value = { isAuthenticated: !!user, user, login, logout, isLoading };

    if (isLoading) {
        return <div style={{ padding: '40px', textAlign: 'center', color: 'white' }}>Loading Session...</div>;
    }

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}