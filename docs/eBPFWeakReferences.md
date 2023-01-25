
**Introduction and problem statement**

The eBPF user-kernel interface is built around a few key objects such as 'Programs', 'Maps' and their interaction. The
'eBPF for Windows' implementation makes extensive use of 'reference counting' to manage the interactions and lifetimes
of these objects.  Code paths 'acquire' references to the required objects for the needed duration and 'release' them
when done.  The reference counting design ensures that the referred-to objects remain valid (i.e., are not deleted) for
the duration of the reference acquisition.

By default, these references are of the 'strong' type, i.e., the referred-to objects are guaranteed to be valid for the
duration of their strong references.  While this property is mandatory in most use cases, it can lead to
'circular reference' instances.  Such instances are perfectly valid and the relationship between a 'Program Array Map'
and an eBPF 'program' is an example of such a relationship.  This circular reference ensures that both the
'Program Array Map' and the eBPF 'program' remain valid for the duration of each other's existence, as they should be.

The user mode application that uses these objects can easily tear down such instances when done, by calling the
provided clean-up API.  The problem arises when the user mode application does not (careless implementation) or is
unable (application crash or a premature exit) to perform this explicit clean-up.

In such cases, the 'Program Array Map' and the 'Program' objects persist even after the user mode application's exit as
the strong circular references make clean-up extremely complex and fragile.  Furthermore, complex edge cases such as
multiple references to the same object from another object (the same program being stored at multiple locations in the
same Prog Array map) leads to complex implementations to ensure proper clean-up.


**Proposed solution**

To correctly handle such edge cases and provide consistent and deterministic clean-up, this proposal introduces the
concept of 'Weak Reference' objects.  A 'Weak Reference' ('weak-ref') object is an intermediate 'secondary' object
that provides the ability to refer to the final 'primary' objects such as Programs and Maps. A weak-ref object exhibits
the following characteristics:

1. A weak-ref object instance is dynamically created during the creation of every primary object instance.
<br>
<br>
2. A weak-ref object is always associated with one and only one primary object instance.  This association is set up
during the primary object's creation.
<br>
<br>
3. A weak-ref object can be disassociated from the primary object it refers to.  This disassociation happens when the
primary object is being destroyed, i.e., when the primary object's ref-count goes to zero. Note that the primary
object's destruction does not affect the weak-ref's ref-count in any manner.
<br>
<br>
4. Once dis-associated, a weak-ref object cannot be made to refer to its previously referred to or another object.
<br>
<br>
5. The life time of a weak-ref object is independent of the referred-to primary object and will always be greater
than that of the referred-to object. To this end, the weak-ref object maintains its own reference count, completely
separate from that of the referred-to object.
<br>
<br>

The ref-count manipulation for both the weak-ref and the referred-to objects can be seen in the table below for the
applicable events:

```
| Event                              | Weak-ref object   | Referred-to object      |
|                                    | ref count         | ref count               |
|------------------------------------|-------------------|-------------------------|
| Referred-to Obj creation           | 1                 | 1                       |
|   (weak-obj is created alongside)  |                   |                         |
|                                    |                   |                         |
| 'borrow' weak-ref, (get ptr to     | increment         | unchanged               |
|   weak-ref associated with         |                   |                         |
|   referred-to obj)                 |                   |                         |
|                                    |                   |                         |
| try-acquire referred-to            | unchanged         | increment, iff non-zero |
|   obj via weak-ref                 |                   |                         |
|                                    |                   |                         |
| release referred-to obj ref        | unchanged         | decrement               |
|   (decrements ref count of         |                   |                         |
|   referred-to obj)                 |                   |                         |
|                                    |                   |                         |
| weak-ref acquire ref               | increment         | unchanged               |
|                                    |                   |                         |
| weak-ref release ref               | decrement         | unchanged               |
|                                    |                   |                         |
| Referred-to obj destruction        | decrement         | decrement               |
|                                    |                   |                         |
| Weak-ref obj destruction           | decrement         | unchanged               |
|                                    |                   |                         |
```

**Weak-ref management API:**

The weak-ref implementation extends the base "ebpf object" management layer and is thus available for all primary
object types.  The weak-ref management API prototypes are in the ```epbf_object.h``` header which provides the
following calls:


```ebpf_weak_reference_t* ebpf_object_weak_reference_get_reference(ebpf_core_object_t* object);```
<br>
The caller typically begins by calling this API to get a weak-ref pointer to the primary object it is interested in.
This call increments the ref count for the weak-ref but does not modify the primary object's ref-count.  The caller now
has a 'token' that it can now use to (conditionally) get the primary object pointer, either right away or at some
later point in time.
<br><br>

```ebpf_core_object_t* ebpf_object_weak_reference_get_object_reference(ebpf_weak_reference_t* weak_reference);```
<br>
The caller uses this call to try to get the primary object pointer.  The 'try' is deliberate in that this call is not
guaranteed to return a valid pointer to the referred-to object as the referred-to object might have been destroyed
(or be in the process of being destroyed).  In such cases, this call will return a NULL.  If the object is still
around, this call increments the ref-count of the referred-to object and returns a valid object pointer to the caller.
The ref-count of the weak-ref object is not modified in this entire process. In case of a valid pointer return, the
caller is responsible for releasing the reference on the returned object.
<br><br>

```void ebpf_object_weak_reference_acquire_reference(ebpf_weak_reference_t* weak_reference);```
<br>
The caller uses this call to increment the ref-count of the weak-ref object, to ensure the weak-ref's validity and/or
longevity in multiple reference scenarios.
<br><br>

```void ebpf_object_weak_reference_release_reference(ebpf_weak_reference_t* weak_reference);```
<br>
The caller uses this call to decrement the ref-count of the weak-ref object, when the weak-ref object is no longer
needed. When the ref-count of the weak-ref goes to zero, it is destroyed.  Note that the weak-ref starts life with a
ref-count of 1 when it is created and associated with the referred-to object (in the context of its referred-to
object's creation) and hence is guaranteed to stay alive until after the primary object is destroyed.


**Conclusion.**

The weak-ref design provides a simple and maintainable solution to the circular reference problem.  With this approach,
the object maps (Prog-Array, Array-Map-of-Maps, Hash-Map-of-Maps) do not need to take a strong reference on the
contained objects anymore.  Instead, they now acquire their weak-ref equivalents and store them alongside their stored
object ids (the per-entry storage space has been suitably expanded to accommodate the weak-ref pointer). When needed,
they can now try to get pointers to the referred-to primary objects with the explicit understanding that they might
not succeed in doing so.

This has made object clean-up very straight-forward as the life-times of the object 'containers', (object arrays, maps)
and the objects they contains are not tied up with each other.