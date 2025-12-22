import { useEffect, useState } from "react";
import { api, type Certificate, type CreateCARequest } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export function CAList() {
  const [cas, setCas] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState<CreateCARequest>({
    commonName: "",
    organization: "",
    country: "",
    validYears: 10,
    keyType: "rsa4096",
    type: "root",
  });

  const fetchCAs = async () => {
    setLoading(true);
    try {
      const data = await api.listCAs();
      setCas(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCAs();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createCA(formData);
      fetchCAs();
      setFormData({ ...formData, commonName: "" });
    } catch (e) {
      alert("Failed to create CA: " + e);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Create Certificate Authority</CardTitle>
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
                <Label>Organization</Label>
                <Input
                  value={formData.organization}
                  onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Country</Label>
                <Input
                  value={formData.country}
                  onChange={(e) => setFormData({ ...formData, country: e.target.value })}
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
                    <SelectItem value="ecp384">ECDSA P-384</SelectItem>
                    <SelectItem value="ecp521">ECDSA P-521</SelectItem>
                    <SelectItem value="ed25519">Ed25519</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Type</Label>
                <Select
                  value={formData.type}
                  onValueChange={(v: any) => setFormData({ ...formData, type: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="root">Root CA</SelectItem>
                    <SelectItem value="intermediate">Intermediate CA</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {formData.type === "intermediate" && (
                <div className="space-y-2">
                  <Label>Parent CA</Label>
                  <Select
                    value={formData.parentCA}
                    onValueChange={(v) => setFormData({ ...formData, parentCA: v })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select Parent CA" />
                    </SelectTrigger>
                    <SelectContent>
                      {cas.map((ca) => (
                        <SelectItem key={ca.id} value={ca.common_name}>
                          {ca.common_name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
            <Button type="submit">Create CA</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Certificate Authorities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full text-sm text-left">
              <thead className="bg-muted/50">
                <tr>
                  <th className="p-4 font-medium">Common Name</th>
                  <th className="p-4 font-medium">Type</th>
                  <th className="p-4 font-medium">Key Type</th>
                  <th className="p-4 font-medium">Serial Number</th>
                  <th className="p-4 font-medium">Expires</th>
                </tr>
              </thead>
              <tbody>
                {cas.map((ca) => (
                  <tr key={ca.id} className="border-t">
                    <td className="p-4">{ca.common_name}</td>
                    <td className="p-4">{ca.type}</td>
                    <td className="p-4">{ca.key_type}</td>
                    <td className="p-4 font-mono text-xs">{ca.serial_number}</td>
                    <td className="p-4">{new Date(ca.expires_at).toLocaleDateString()}</td>
                  </tr>
                ))}
                {cas.length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-4 text-center text-muted-foreground">
                      No CAs found
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
