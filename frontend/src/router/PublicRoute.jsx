import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

function PublicRoute(){
    const { isAuthenticated, isLoading } = useAuth();

    // TODO: Make this consistent for loading in ProtectedRoute and maybe a spinner?
    if (isLoading){
        return <div>Loading...</div>
    }

    if(isAuthenticated){
        return <Navigate to="dashboard" replace />;
    }

    return <Outlet />
}

export default PublicRoute;