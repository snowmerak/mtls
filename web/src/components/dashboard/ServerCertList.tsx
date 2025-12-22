import { useEffect, useState } from "react";
import { api, type Certificate, type CreateServerCertRequest } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export function ServerCertList() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [cas, setCas] = useState<Certificate[]>([]);
  const [formData, setFormData] = useState<CreateServerCertRequest>({
    commonName: "",
    organization: "",
    dnsNames: [],
    ipAddresses: [],
    validYears: 5,
    keyType: "rsa2048",
    caName: "",
  });
  const [dnsInput, setDnsInput] = useState("");
  const [ipInput, setIpInput] = useState("");

  const fetchData = async () => {
    try {
      const [certData, caData] = await Promise.all([
        api.listServerCerts(),
        api.listCAs(),
      ]);
      setCerts(certData);
      setCas(caData);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const req = {
        ...formData,
        dnsNames: dnsInput.split(",").map(s => s.trim()).filter(s => s),
        ipAddresses: ipInput.split(",").map(s => s.trim()).filter(s => s),
      };
      await api.createServerCert(req);
      fetchData();
      setFormData({ ...formData, commonName: "" });
      setDnsInput("");
      setIpInput("");
    } catch (e) {
      alert("Failed to create certificate: " + e);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Create Server Certificate</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Common Name</Label>
                <Input
                  value={formData.commonName}
                  onChange={(e) => setFormData({ ...formData, commonName: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Issuer CA</Label>
                <Select
                  value={formData.caName}
                  onValueChange={(v) => setFormData({ ...formData, caName: v })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select CA" />
                  </SelectTrigger>
                  <SelectContent>
                    {cas.map((ca) => (
                      <SelectItem key={ca.id} value={ca.commonName}>
                        {ca.commonName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Organization</Label>
                <Input
                  value={formData.organization}
                  onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Valid Years</Label>
                <Input
                  type="number"
                  value={formData.validYears}
                  onChange={(e) => setFormData({ ...formData, validYears: parseInt(e.target.value) })}
                />
              </div>
              <div className="space-y-2">
                <Label>DNS Names (comma separated)</Label>
                <Input
                  value={dnsInput}
                  onChange={(e) => setDnsInput(e.target.value)}
                  placeholder="example.com, www.example.com"
                />
              </div>
              <div className="space-y-2">
                <Label>IP Addresses (comma separated)</Label>
                <Input
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  placeholder="127.0.0.1, 192.168.1.1"
                />
              </div>
              <div className="space-y-2">
                <Label>Key Type</Label>
                <Select
                  value={formData.keyType}
                  onValueChange={(v) => setFormData({ ...formData, keyType: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="rsa2048">RSA 2048</SelectItem>
                    <SelectItem value="rsa4096">RSA 4096</SelectItem>
                    <SelectItem value="ecp256">ECDSA P-256</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Button type="submit">Create Certificate</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Server Certificates</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm text-left">
              <thead className="bg-muted/50">
                <tr>
                  <th className="p-4 font-medium">Common Name</th>
                  <th className="p-4 font-medium">Issuer</th>
                  <th className="p-4 font-medium">Serial Number</th>
                  <th className="p-4 font-medium">Expires</th>
                </tr>
              </thead>
              <tbody>
                {certs.map((cert) => (
                  <tr key={cert.id} className="border-t">
                    <td className="p-4">{cert.commonName}</td>
                    <td className="p-4">{cert.issuer?.commonName || "-"}</td>
                    <td className="p-4 font-mono text-xs">{cert.serialNumber}</td>
                    <td className="p-4">{new Date(cert.expiresAt).toLocaleDateString()}</td>
                  </tr>
                ))}
                {certs.length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-4 text-center text-muted-foreground">
                      No certificates found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
