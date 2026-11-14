"""VerityOS - Trust Engine Package.

This package provides trust scoring, policy evaluation, source reliability verification,
freshness verification, consistency checking, and cryptographic integrity checking
for the VerityOS autonomous operating system.
"""

def evaluate_trust_engine(verification_packet: dict) -> dict:
    """Primary integration function exposed to Member 1 and the VerityOS system.
    
    Lazily imports the engine coordinator to allow independent use of submodules
    without hard circular dependencies.
    """
    from trust_engine.trust_engine import evaluate_trust_engine as _evaluate
    return _evaluate(verification_packet)


__all__ = ["evaluate_trust_engine"]
__version__ = "0.1.0"
