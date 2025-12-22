import { useState } from "react";
import { Button } from "@/components/ui/button";
import { CAList } from "./CAList";
import { ServerCertList } from "./ServerCertList";
import { ClientCertList } from "./ClientCertList";

export function Dashboard() {
  const [activeTab, setActiveTab] = useState<"ca" | "server" | "client">("ca");

  return (
    <div className="space-y-6">
      <div className="flex space-x-4 border-b pb-4">
        <Button
          variant={activeTab === "ca" ? "default" : "ghost"}
          onClick={() => setActiveTab("ca")}
        >
          Certificate Authorities
        </Button>
        <Button
          variant={activeTab === "server" ? "default" : "ghost"}
          onClick={() => setActiveTab("server")}
        >
          Server Certificates
        </Button>
        <Button
          variant={activeTab === "client" ? "default" : "ghost"}
          onClick={() => setActiveTab("client")}
        >
          Client Certificates
        </Button>
      </div>

      {activeTab === "ca" && <CAList />}
      {activeTab === "server" && <ServerCertList />}
      {activeTab === "client" && <ClientCertList />}
    </div>
  );
}
