from enum import Enum


class UserRole(str, Enum):
    """
    Role definitions for RBAC.
    USERA: Base user (e.g., standard user persona)
    USERB: Elevated user / Moderator / Admin persona
    USERC: Super Admin / System Administrator persona

    You can easily alias or rename these roles for your hackathon personas.
    """
    USERA = "USERA"
    USERB = "USERB"
    USERC = "USERC"

    @property
    def hierarchy_level(self) -> int:
        """Returns integer weight for role hierarchy comparison."""
        hierarchy = {
            UserRole.USERA: 1,
            UserRole.USERB: 2,
            UserRole.USERC: 3,
        }
        return hierarchy.get(self, 0)

    def has_permission_over(self, target_role: "UserRole") -> bool:
        """Returns True if self has strictly higher authority than target_role."""
        return self.hierarchy_level > target_role.hierarchy_level

    def is_at_least(self, required_role: "UserRole") -> bool:
        """Returns True if self is equal to or higher in hierarchy than required_role."""
        return self.hierarchy_level >= required_role.hierarchy_level
