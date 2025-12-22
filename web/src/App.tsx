import { Dashboard } from "@/components/dashboard/Dashboard";
import "./index.css";

export function App() {
  return (
    <div className="container mx-auto p-8 w-[88%] max-w-none">
      <div className="mb-8 text-center">
        <h1 className="text-4xl font-bold mb-2">mTLS Manager</h1>
        <p className="text-muted-foreground">Manage your Certificate Authorities and Certificates</p>
      </div>
      <Dashboard />
    </div>
  );
}

export default App;
