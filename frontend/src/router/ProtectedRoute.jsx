import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

function ProtectedRoute(){
    const { isAuthenticated, isLoading } = useAuth();

    if(isLoading){
        return <div>Loading...</div>;
    }

    if(!isAuthenticated){
        return <Navigate to="/login" replace />;
    }

    return <Outlet />;
}

export default ProtectedRoute;