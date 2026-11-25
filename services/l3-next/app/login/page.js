"use client";

import { useState } from "react";

export default function Login() {
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    
    setError("Local sign-in is disabled. Use the corporate SSO gateway.");
  };

  return (
    <div className="container-fluid bg-light min-vh-100 d-flex align-items-center justify-content-center">
      <div className="card shadow p-4" style={{ maxWidth: "400px" }}>
        <div className="card-body">
          <h1 className="card-title text-center mb-4 fw-bold">Admin Login</h1>

          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="username" className="form-label">
                Username
              </label>
              <input
                id="username"
                type="text"
                className="form-control"
                autoComplete="username"
              />
            </div>
            <div className="mb-4">
              <label htmlFor="password" className="form-label">
                Password
              </label>
              <input
                id="password"
                type="password"
                className="form-control"
                autoComplete="current-password"
              />
            </div>
            <button type="submit" className="btn btn-primary w-100">
              Continue with SSO
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
