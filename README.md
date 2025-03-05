A Driver used to modify a given process' token by modifying the `_TOKEN._SEP_TOKEN_PRIVILEGES.Present` and `_TOKEN._SEP_TOKEN_PRIVILEGES.Enabled` fields that resides in the `_TOKEN` data structure within the `_EPROCESS` object of the process in kernel space.

![image](https://github.com/user-attachments/assets/39e511e1-5f5f-4f80-aab2-f6a70aefb5d7)


NOTE:
- Use it in a careful and responsible way.
- Offsets used in the driver may vary between different windows builds.
