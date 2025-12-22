const API_BASE = "http://localhost:8080";

export interface Certificate {
  id: number;
  type: string;
  common_name: string;
  serial_number: string;
  status: string;
  organization?: string;
  country?: string;
  created_at: string;
  expires_at: string;
  key_type?: string;
  fingerprint?: string;
  cert_path?: string;
  key_path?: string;
  edges?: {
    issuer?: Certificate;
  };
  dns_names?: string[];
  ip_addresses?: string[];
}

export interface CreateCARequest {
  commonName: string;
  organization?: string;
  country?: string;
  validYears?: number;
  keyType?: string;
  type?: "root" | "intermediate";
  parentCA?: string;
}

export interface CreateServerCertRequest {
  commonName: string;
  organization?: string;
  dnsNames?: string[];
  ipAddresses?: string[];
  validYears?: number;
  keyType?: string;
  caName: string;
}

export interface CreateClientCertRequest {
  commonName: string;
  organization?: string;
  dnsNames?: string[];
  ipAddresses?: string[];
  validYears?: number;
  keyType?: string;
  caName: string;
}

export const api = {
  listCAs: async (): Promise<Certificate[]> => {
    const res = await fetch(`${API_BASE}/ca`);
    const json = await res.json();
    return json.data || [];
  },

  createCA: async (req: CreateCARequest) => {
    const res = await fetch(`${API_BASE}/ca`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  listServerCerts: async (): Promise<Certificate[]> => {
    const res = await fetch(`${API_BASE}/cert/server`);
    const json = await res.json();
    return json.data || [];
  },

  createServerCert: async (req: CreateServerCertRequest) => {
    const res = await fetch(`${API_BASE}/cert/server`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  listClientCerts: async (): Promise<Certificate[]> => {
    const res = await fetch(`${API_BASE}/cert/client`);
    const json = await res.json();
    return json.data || [];
  },

  createClientCert: async (req: CreateClientCertRequest) => {
    const res = await fetch(`${API_BASE}/cert/client`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
};
