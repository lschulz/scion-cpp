MPTCP over SCION:
- Scitra identifies SCION MPTCP subflows by SCION host address and port of the sender and receiver,
  and the SCION path. This enabled multiple paths between the the same set of SCION endpoints.
- The SCION path of a subflow must not change during the subflow's lifetime. The path is selected
  by the sender of the first SYN. The receiver must store this path and only respond on this path.
  To change paths, new subflow must be established on the new SCION paths. This ensures that Scitra
  can correctly translate MPTCP/SCION back to MPTCP/IP.
