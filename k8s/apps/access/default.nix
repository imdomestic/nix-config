# 给人用的集群账号。这里只有身份和授权，没有凭据：本机的 kubeconfig 每次通过
# ssh root@tank 现签一个短期 token，见 home/modules/kube。
{
  applications.access = {
    namespace = "kube-system";
    createNamespace = false;

    resources = {
      serviceAccounts.hank = {};
      clusterRoleBindings.hank-cluster-admin = {
        roleRef = {
          apiGroup = "rbac.authorization.k8s.io";
          kind = "ClusterRole";
          name = "cluster-admin";
        };
        subjects = [
          {
            kind = "ServiceAccount";
            name = "hank";
            namespace = "kube-system";
          }
        ];
      };
    };
  };
}
